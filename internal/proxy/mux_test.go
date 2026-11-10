package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/dlp"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func newIPv4Server(t *testing.T, handler http.Handler) *httptest.Server {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
		return nil
	}
	ts := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	ts.Start()
	return ts
}

func closeServer(ts *httptest.Server) {
	if ts != nil {
		ts.CloseClientConnections()
		ts.Close()
	}
}

func TestAgentSessionBridge_ParallelDialAndMultiplexing(t *testing.T) {
	// Server 1 (Database MCP)
	s1 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("event: endpoint\ndata: /message?sessionId=s1-upstream-123\n\n"))
		flusher.Flush()

		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"msg-1\",\"result\":{\"source\":\"db\"}}\n\n"))
		flusher.Flush()

		<-r.Context().Done()
	}))
	defer closeServer(s1)

	// Server 2 (API MCP)
	s2 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("event: endpoint\ndata: /message?sessionId=s2-upstream-456\n\n"))
		flusher.Flush()

		time.Sleep(80 * time.Millisecond)
		w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"msg-2\",\"result\":{\"source\":\"api\"}}\n\n"))
		flusher.Flush()

		<-r.Context().Done()
	}))
	defer closeServer(s2)

	agentDir := "./agents"
	agentName := "dual-mux-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)
	defer os.RemoveAll(agentDir)

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-dual-1",
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-db", Name: "mock-db", Type: "sse", URLOrCommand: s1.URL + "/sse"},
			{ID: "proto-api", Name: "mock-api", Type: "sse", URLOrCommand: s2.URL + "/sse"},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	if err := os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644); err != nil {
		t.Fatalf("Failed to write config.json: %v", err)
	}

	proxy := NewSSEProxy(0, s1.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer reqCancel()

	clientReq, err := http.NewRequestWithContext(reqCtx, "GET", gwServer.URL+"/sse/"+agentName, nil)
	if err != nil {
		t.Fatalf("Failed to build client request: %v", err)
	}

	clientResp, err := http.DefaultClient.Do(clientReq)
	if err != nil {
		t.Fatalf("Client connection failed: %v", err)
	}
	defer clientResp.Body.Close()

	if clientResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got: %d", clientResp.StatusCode)
	}

	reader := bufio.NewReader(clientResp.Body)

	// Event 1 should be unified endpoint with cl- session ID
	line1, _ := reader.ReadString('\n')
	line2, _ := reader.ReadString('\n')
	reader.ReadString('\n') // Empty line

	if !strings.HasPrefix(line1, "event: endpoint") {
		t.Fatalf("Expected event: endpoint, got: %s", line1)
	}
	if !strings.Contains(line2, "/sse/"+agentName+"/message?sessionId=cl-") {
		t.Fatalf("Expected unified endpoint path with cl- sessionId, got: %s", line2)
	}

	endpointURL := strings.TrimPrefix(strings.TrimSpace(line2), "data: ")
	u, _ := url.Parse(endpointURL)
	clientSessionID := u.Query().Get("sessionId")
	if clientSessionID == "" {
		t.Fatalf("Client session ID was empty in endpoint: %s", endpointURL)
	}

	// Verify bridge registered in session manager
	bridge, hasBridge := proxy.SessionManager().GetBridge(clientSessionID)
	if !hasBridge || bridge == nil {
		t.Fatalf("Expected bridge to be registered in session manager for %s", clientSessionID)
	}
	defer bridge.Cancel()

	// Wait for upstream messages to be multiplexed
	receivedMessages := make(map[string]bool)
	for i := 0; i < 2; i++ {
		evLine, _ := reader.ReadString('\n')
		dataLine, _ := reader.ReadString('\n')
		reader.ReadString('\n') // Empty line

		if strings.HasPrefix(evLine, "event: message") {
			data := strings.TrimPrefix(strings.TrimSpace(dataLine), "data: ")
			if strings.Contains(data, "\"source\":\"db\"") {
				receivedMessages["db"] = true
			} else if strings.Contains(data, "\"source\":\"api\"") {
				receivedMessages["api"] = true
			}
		}
	}

	if !receivedMessages["db"] || !receivedMessages["api"] {
		t.Fatalf("Expected both db and api messages multiplexed to client, got: %v", receivedMessages)
	}
}

func TestAgentSessionBridge_GracefulDegradation(t *testing.T) {
	s1 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("event: endpoint\ndata: /message?sessionId=healthy-123\n\n"))
		flusher.Flush()
		<-r.Context().Done()
	}))
	defer closeServer(s1)

	deadURL := "http://127.0.0.1:54321/sse"

	agentDir := "./agents"
	agentName := "degraded-mux-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)
	defer os.RemoveAll(agentDir)

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-degraded-1",
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-healthy", Name: "healthy-mcp", Type: "sse", URLOrCommand: s1.URL + "/sse"},
			{ID: "proto-dead", Name: "dead-mcp", Type: "sse", URLOrCommand: deadURL},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	_ = os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644)

	proxy := NewSSEProxy(0, s1.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer reqCancel()

	clientReq, _ := http.NewRequestWithContext(reqCtx, "GET", gwServer.URL+"/sse/"+agentName, nil)
	clientResp, err := http.DefaultClient.Do(clientReq)
	if err != nil {
		t.Fatalf("Client request failed: %v", err)
	}
	defer clientResp.Body.Close()

	if clientResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK Graceful Degradation, got: %d", clientResp.StatusCode)
	}

	reader := bufio.NewReader(clientResp.Body)
	line1, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line1, "event: endpoint") {
		t.Fatalf("Expected event: endpoint, got: %s", line1)
	}
}

func TestAgentSessionBridge_ToolRoutingWithBridge(t *testing.T) {
	dbCalled := make(chan string, 1)
	s1 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=db-session-777\n\n"))
			flusher.Flush()
			<-r.Context().Done()
			return
		}
		if r.Method == http.MethodPost {
			sess := r.URL.Query().Get("sessionId")
			body, _ := io.ReadAll(r.Body)
			dbCalled <- sess + "::" + string(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","id":100,"result":{"status":"db_ok"}}`))
			return
		}
	}))
	defer closeServer(s1)

	apiCalled := make(chan string, 1)
	s2 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=api-session-888\n\n"))
			flusher.Flush()
			<-r.Context().Done()
			return
		}
		if r.Method == http.MethodPost {
			sess := r.URL.Query().Get("sessionId")
			body, _ := io.ReadAll(r.Body)
			apiCalled <- sess + "::" + string(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","id":200,"result":{"status":"api_ok"}}`))
			return
		}
	}))
	defer closeServer(s2)

	agentDir := "./agents"
	agentName := "routing-bridge-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)
	defer os.RemoveAll(agentDir)

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-route-1",
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-db", Name: "dummy-mcp-db", Type: "sse", URLOrCommand: s1.URL + "/sse"},
			{ID: "proto-api", Name: "dummy-mcp-api", Type: "sse", URLOrCommand: s2.URL + "/sse"},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	_ = os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644)

	// Write tools manifest
	toolsManifest := `[
		{"name": "query_users", "canonical_name": "query_users", "protocol_name": "dummy-mcp-db"},
		{"name": "deploy_service", "canonical_name": "deploy_service", "protocol_name": "dummy-mcp-api"}
	]`
	_ = os.WriteFile(filepath.Join(agentCurrent, "tools_manifest.json"), []byte(toolsManifest), 0644)

	proxy := NewSSEProxy(0, s1.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	// 1. Client connects GET /sse/routing-bridge-agent
	clientReq, _ := http.NewRequest("GET", gwServer.URL+"/sse/"+agentName, nil)
	clientResp, err := http.DefaultClient.Do(clientReq)
	if err != nil {
		t.Fatalf("Failed to open SSE: %v", err)
	}
	defer clientResp.Body.Close()

	reader := bufio.NewReader(clientResp.Body)
	reader.ReadString('\n') // event: endpoint
	line2, _ := reader.ReadString('\n')
	reader.ReadString('\n') // empty line

	endpointURL := strings.TrimPrefix(strings.TrimSpace(line2), "data: ")
	u, _ := url.Parse(endpointURL)
	clientSessionID := u.Query().Get("sessionId")
	if clientSessionID == "" {
		t.Fatalf("Client session ID was empty in endpoint: %s", endpointURL)
	}

	bridge, hasBridge := proxy.SessionManager().GetBridge(clientSessionID)
	if hasBridge && bridge != nil {
		defer bridge.Cancel()
	}

	// 2. Send POST to call tool "deploy_service" (should route to API MCP on s2 with sessionId=api-session-888)
	postPayload := `{"jsonrpc":"2.0","id":200,"method":"tools/call","params":{"name":"deploy_service","arguments":{"app":"portal"}}}`
	postReq, _ := http.NewRequest("POST", gwServer.URL+"/sse/"+agentName+"/message?sessionId="+clientSessionID, bytes.NewBufferString(postPayload))
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from tool execution, got: %d", postResp.StatusCode)
	}

	select {
	case apiCall := <-apiCalled:
		if !strings.HasPrefix(apiCall, "api-session-888::") {
			t.Fatalf("Expected call to API MCP with upstream sessionId 'api-session-888', got: %s", apiCall)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for API MCP call")
	}
}

func TestAgentSessionBridge_JITLazyReconnectOnDegraded(t *testing.T) {
	// Server 1 is always healthy (DB MCP)
	s1 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=db-sess-111\n\n"))
			flusher.Flush()
			<-r.Context().Done()
			return
		}
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","id":10,"result":{"db":"ok"}}`))
			return
		}
	}))
	defer closeServer(s1)

	// Protocol 2 initially points to an offline port
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test requiring loopback socket: %v", err)
		return
	}
	server2Addr := l.Addr().String()
	l.Close() // Initially closed

	server2URL := "http://" + server2Addr

	agentDir := "./agents"
	agentName := "jit-reconnect-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)
	defer os.RemoveAll(agentDir)

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-jit-1",
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-db", Name: "dummy-mcp-db", Type: "sse", URLOrCommand: s1.URL + "/sse"},
			{ID: "proto-api", Name: "dummy-mcp-api", Type: "sse", URLOrCommand: server2URL + "/sse"},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	_ = os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644)

	toolsManifest := `[
		{"name": "query_users", "canonical_name": "query_users", "protocol_name": "dummy-mcp-db"},
		{"name": "deploy_service", "canonical_name": "deploy_service", "protocol_name": "dummy-mcp-api"}
	]`
	_ = os.WriteFile(filepath.Join(agentCurrent, "tools_manifest.json"), []byte(toolsManifest), 0644)

	proxy := NewSSEProxy(0, s1.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	// 1. Client connects GET /sse/jit-reconnect-agent (Server 2 is offline -> marked DEGRADED)
	clientReq, _ := http.NewRequest("GET", gwServer.URL+"/sse/"+agentName, nil)
	clientResp, err := http.DefaultClient.Do(clientReq)
	if err != nil {
		t.Fatalf("Failed to open SSE: %v", err)
	}
	defer clientResp.Body.Close()

	reader := bufio.NewReader(clientResp.Body)
	reader.ReadString('\n') // event: endpoint
	line2, _ := reader.ReadString('\n')
	reader.ReadString('\n') // empty line

	endpointURL := strings.TrimPrefix(strings.TrimSpace(line2), "data: ")
	u, _ := url.Parse(endpointURL)
	clientSessionID := u.Query().Get("sessionId")
	if clientSessionID == "" {
		t.Fatalf("Client session ID was empty in endpoint: %s", endpointURL)
	}

	bridge, hasBridge := proxy.SessionManager().GetBridge(clientSessionID)
	if !hasBridge || bridge == nil {
		t.Fatalf("Bridge not found")
	}
	defer bridge.Cancel()

	apiUp := bridge.GetUpstream("proto-api")
	if apiUp == nil || apiUp.GetStatus() != "DEGRADED" {
		t.Fatalf("Expected proto-api to be DEGRADED initially, got: %v", apiUp)
	}
	// 4. Now launch mock server for dummy-mcp-api on server2Addr (JIT recovery target)
	l2, err := net.Listen("tcp4", server2Addr)
	if err != nil {
		t.Fatalf("Failed to re-bind server2 on %s: %v", server2Addr, err)
	}
	s2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=api-reconnected-222\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
			<-r.Context().Done()
			return
		} else if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"api_reconnected":true,"sessionId":"` + r.URL.Query().Get("sessionId") + `"}}`))
		}
	}))
	s2.Listener = l2
	s2.Start()
	defer closeServer(s2)

	// 5. Send tool call targeting dummy-mcp-api -> triggers JIT reconnect
	toolBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy_service","arguments":{}}}`)
	postReq, _ := http.NewRequest("POST", gwServer.URL+"/sse/"+agentName+"/message?sessionId="+clientSessionID, bytes.NewBuffer(toolBody))
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("Tool call POST request failed: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		respB, _ := io.ReadAll(postResp.Body)
		t.Fatalf("Expected 200 OK after JIT lazy reconnect, got status: %d body: %s", postResp.StatusCode, string(respB))
	}

	var jsonResult map[string]interface{}
	json.NewDecoder(postResp.Body).Decode(&jsonResult)
	resObj, _ := jsonResult["result"].(map[string]interface{})
	if resObj["api_reconnected"] != true {
		t.Fatalf("Expected api_reconnected to be true, got: %v", jsonResult)
	}
	if resObj["sessionId"] != "api-reconnected-222" {
		t.Fatalf("Expected upstream sessionId 'api-reconnected-222', got: %v", resObj["sessionId"])
	}

	// Verify bridge status updated to READY
	apiUpAfter := bridge.GetUpstream("proto-api")
	if apiUpAfter == nil || apiUpAfter.GetStatus() != "READY" {
		t.Fatalf("Expected proto-api status to be updated to READY, got: %v", apiUpAfter)
	}
}

func TestDualTransport_StatefulSSE_vs_StatelessHTTP(t *testing.T) {
	mcpServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			w.Write([]byte("event: endpoint\ndata: /message?sessionId=be-sess-777\n\n"))
			flusher.Flush()
			<-r.Context().Done()
			return
		}
		if r.Method == http.MethodPost {
			sess := r.URL.Query().Get("sessionId")
			w.Header().Set("Content-Type", "application/json")
			if sess != "" {
				// Stateful SSE mode response
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// Stateless synchronous HTTP mode response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","id":55,"result":{"content":[{"type":"text","text":"User John Doe, Card 4532-1122-3344-5566"}]}}`))
			return
		}
	}))
	defer closeServer(mcpServer)

	agentDir := "./agents"
	agentName := "dual-transport-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)
	defer os.RemoveAll(agentDir)

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-dual-1",
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-db", Name: "dummy-db", Type: "sse", URLOrCommand: mcpServer.URL + "/sse"},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	_ = os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644)

	toolsManifest := `[
		{"name": "query_users", "canonical_name": "query_users", "protocol_name": "dummy-db"}
	]`
	_ = os.WriteFile(filepath.Join(agentCurrent, "tools_manifest.json"), []byte(toolsManifest), 0644)

	// Create pipeline with DLP filter masking credit cards
	patterns := []config.DLPPattern{
		{Name: "card", Regex: `\b\d{4}-\d{4}-\d{4}-\d{4}\b`, Action: "mask"},
	}
	dlpFilter, err := dlp.NewDLPFilter(true, nil, patterns)
	if err != nil {
		t.Fatalf("Failed to create DLP filter: %v", err)
	}
	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.Filter{dlpFilter})

	proxy := NewSSEProxy(0, mcpServer.URL, pipeline, agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	// 1. STATEFUL SSE TRANSPORT TEST
	sseReq, _ := http.NewRequest("GET", gwServer.URL+"/sse/"+agentName, nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("Failed to open SSE connection: %v", err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)
	reader.ReadString('\n') // event: endpoint
	line2, _ := reader.ReadString('\n')
	reader.ReadString('\n') // blank

	endpointURL := strings.TrimPrefix(strings.TrimSpace(line2), "data: ")
	u, _ := url.Parse(endpointURL)
	clientSessionID := u.Query().Get("sessionId")
	if clientSessionID == "" {
		t.Fatalf("Expected client sessionId in endpoint data, got: %s", endpointURL)
	}

	if br, ok := proxy.SessionManager().GetBridge(clientSessionID); ok && br != nil {
		defer br.Cancel()
	}

	// Post tool call in stateful mode
	postPayload := `{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"query_users","arguments":{}}}`
	postReq, _ := http.NewRequest("POST", gwServer.URL+"/sse/"+agentName+"/message?sessionId="+clientSessionID, bytes.NewBufferString(postPayload))
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("Stateful POST failed: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("Expected HTTP 202 Accepted for stateful SSE tool POST, got: %d", postResp.StatusCode)
	}

	// 2. STATELESS STREAMABLE HTTP TRANSPORT TEST (via /mcp/{agent})
	statelessPayload := `{"jsonrpc":"2.0","id":55,"method":"tools/call","params":{"name":"query_users","arguments":{}}}`
	statelessReq, _ := http.NewRequest("POST", gwServer.URL+"/mcp/"+agentName, bytes.NewBufferString(statelessPayload))
	statelessReq.Header.Set("Content-Type", "application/json")
	statelessResp, err := http.DefaultClient.Do(statelessReq)
	if err != nil {
		t.Fatalf("Stateless POST failed: %v", err)
	}
	defer statelessResp.Body.Close()

	if statelessResp.StatusCode != http.StatusOK {
		respBodyBytes, _ := io.ReadAll(statelessResp.Body)
		t.Fatalf("Expected HTTP 200 OK for stateless HTTP tool POST, got status: %d body: %s", statelessResp.StatusCode, string(respBodyBytes))
	}

	statelessBodyBytes, _ := io.ReadAll(statelessResp.Body)
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(statelessBodyBytes, &jsonResp); err != nil {
		t.Fatalf("Failed to parse JSON-RPC response: %v", err)
	}

	resMap, _ := jsonResp["result"].(map[string]interface{})
	contentArr, _ := resMap["content"].([]interface{})
	if len(contentArr) == 0 {
		t.Fatalf("Expected result content in stateless response, got: %s", string(statelessBodyBytes))
	}
	firstContent, _ := contentArr[0].(map[string]interface{})
	textVal, _ := firstContent["text"].(string)

	// Verify DLP masked the credit card in the synchronous response
	if !strings.Contains(textVal, "[REDACTED") {
		t.Fatalf("Expected DLP masking [REDACTED] in synchronous response, got: %s", textVal)
	}
	if strings.Contains(textVal, "4532-1122-3344-5566") {
		t.Fatalf("Raw credit card leaked in synchronous response: %s", textVal)
	}
}

func TestAgentSessionBridge_LifecycleCleanupAndGoroutineLeak(t *testing.T) {
	// Upstream 1
	var u1Closed atomic.Bool
	u1 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("event: endpoint\ndata: /message?sessionId=u1-sess\n\n"))
		flusher.Flush()
		<-r.Context().Done()
		u1Closed.Store(true)
	}))
	defer closeServer(u1)

	// Upstream 2
	var u2Closed atomic.Bool
	u2 := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("event: endpoint\ndata: /message?sessionId=u2-sess\n\n"))
		flusher.Flush()
		<-r.Context().Done()
		u2Closed.Store(true)
	}))
	defer closeServer(u2)

	agentDir := "./agents"
	agentName := "leak-test-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)
	defer os.RemoveAll(agentDir)

	agentCfg := agent.RouteConfig{
		AgentID:     "agent-leak-1",
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{ID: "proto-1", Name: "upstream-1", Type: "sse", URLOrCommand: u1.URL + "/sse"},
			{ID: "proto-2", Name: "upstream-2", Type: "sse", URLOrCommand: u2.URL + "/sse"},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	_ = os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644)

	proxy := NewSSEProxy(0, u1.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	// 1. Client connects to Gateway
	clientCtx, clientCancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(clientCtx, "GET", gwServer.URL+"/sse/"+agentName, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to open SSE connection: %v", err)
	}

	reader := bufio.NewReader(resp.Body)
	line1, _ := reader.ReadString('\n') // event: endpoint
	line2, _ := reader.ReadString('\n') // data: ...
	reader.ReadString('\n')             // blank line

	if !strings.Contains(line1, "endpoint") {
		t.Fatalf("Expected endpoint event, got: %s", line1)
	}

	endpointData := strings.TrimPrefix(strings.TrimSpace(line2), "data: ")
	u, _ := url.Parse(endpointData)
	clientSessionID := u.Query().Get("sessionId")

	// Verify bridge registered
	_, hasBridge := proxy.SessionManager().GetBridge(clientSessionID)
	if !hasBridge {
		t.Fatalf("Expected session bridge registered in session manager for %s", clientSessionID)
	}

	// 2. Client terminates connection (Context cancellation)
	clientCancel()
	resp.Body.Close()

	// 3. Wait for gateway cleanup defer to execute
	time.Sleep(100 * time.Millisecond)

	// Verify session bridge evicted from memory
	_, hasBridgeAfter := proxy.SessionManager().GetBridge(clientSessionID)
	if hasBridgeAfter {
		t.Fatalf("Expected session bridge evicted after disconnect")
	}

	// Verify upstreams received context cancellation
	if !u1Closed.Load() || !u2Closed.Load() {
		t.Fatalf("Expected both upstreams to be closed, u1Closed=%v, u2Closed=%v", u1Closed.Load(), u2Closed.Load())
	}
}

func TestStreamableHTTP_IngressRouting(t *testing.T) {
	var receivedAuth atomic.Value
	var receivedCustom atomic.Value
	receivedAuth.Store("")
	receivedCustom.Store("")

	// Mock upstream Streamable HTTP MCP server
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		receivedAuth.Store(r.Header.Get("Authorization"))
		receivedCustom.Store(r.Header.Get("X-Custom-Api-Key"))

		var rpc struct {
			ID     interface{}     `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rpc)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result": map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": "Streamable HTTP Tool Execution Success"},
				},
			},
		})
	})
	upstreamServer := newIPv4Server(t, upstreamHandler)
	defer closeServer(upstreamServer)

	// Configure agent with Streamable HTTP protocol
	agentDir := t.TempDir()
	agentName := "streamable-agent"
	agentCurrent := filepath.Join(agentDir, agentName, "current")
	_ = os.MkdirAll(agentCurrent, 0755)

	agentCfg := agent.RouteConfig{
		AgentName:   agentName,
		RoutingMode: "aggregated",
		Protocols: []agent.ProtocolConfig{
			{
				ID:           "proto-streamable",
				Name:         "streamable-mcp",
				Type:         "http",
				URLOrCommand: upstreamServer.URL + "/mcp",
				AuthToken:    "upstream-bearer-secret",
				Headers:      map[string]string{"X-Custom-Api-Key": "custom-val-123"},
			},
		},
	}
	cfgBytes, _ := json.Marshal(agentCfg)
	_ = os.WriteFile(filepath.Join(agentCurrent, "config.json"), cfgBytes, 0644)

	toolsManifest := `[
		{"name": "fetch_doc", "canonical_name": "fetch_doc", "protocol_name": "streamable-mcp"}
	]`
	_ = os.WriteFile(filepath.Join(agentCurrent, "tools_manifest.json"), []byte(toolsManifest), 0644)

	keyStore := auth.NewMemoryKeyStore()
	clientToken, _, err := keyStore.GenerateKey("Test Ingress Client", "Developer")
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	proxy := NewSSEProxy(0, upstreamServer.URL, filter.NewPipeline(nil), agent.NewFSRepository(agentDir, ""), nil, config.UserContextConfig{})
	proxy.SetKeyValidator(keyStore)
	gwServer := newIPv4Server(t, proxy.Handler())
	defer closeServer(gwServer)

	// 1. Client connects GET /sse/streamable-agent
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	clientReq, _ := http.NewRequestWithContext(clientCtx, "GET", gwServer.URL+"/sse/"+agentName, nil)
	clientReq.Header.Set("Authorization", "Bearer "+clientToken)
	clientResp, err := http.DefaultClient.Do(clientReq)
	if err != nil {
		t.Fatalf("Failed to open SSE: %v", err)
	}
	defer clientResp.Body.Close()

	reader := bufio.NewReader(clientResp.Body)
	line1, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read SSE line 1: %v", err)
	}
	line2, _ := reader.ReadString('\n')
	reader.ReadString('\n') // blank line

	if !strings.Contains(line1, "endpoint") {
		t.Fatalf("Expected endpoint event, got: %s", line1)
	}

	endpointURL := strings.TrimPrefix(strings.TrimSpace(line2), "data: ")
	u, _ := url.Parse(endpointURL)
	clientSessionID := u.Query().Get("sessionId")
	if clientSessionID == "" {
		t.Fatalf("Client session ID was empty in endpoint: %s", endpointURL)
	}

	// Verify session bridge registered and upstream marked READY
	bridge, hasBridge := proxy.SessionManager().GetBridge(clientSessionID)
	if !hasBridge || bridge == nil {
		t.Fatalf("Expected bridge registered for %s", clientSessionID)
	}
	upSess := bridge.GetUpstream("proto-streamable")
	if upSess == nil {
		upSess = bridge.GetUpstream("streamable-mcp")
	}
	if upSess == nil {
		t.Fatal("Expected upstream session for streamable-mcp in bridge")
	}
	if !upSess.IsStreamableHTTP() {
		t.Error("Expected upstream to be marked as Streamable HTTP")
	}
	if upSess.GetStatus() != "READY" {
		t.Errorf("Expected status READY, got %s", upSess.GetStatus())
	}

	// 2. Client calls tool "fetch_doc" via POST with client authorization token
	postPayload := `{"jsonrpc":"2.0","id":"call-stream-1","method":"tools/call","params":{"name":"fetch_doc","arguments":{"docId":"doc-42"}}}`
	postReq, _ := http.NewRequest("POST", gwServer.URL+"/sse/"+agentName+"/message?sessionId="+clientSessionID, bytes.NewBufferString(postPayload))
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Authorization", "Bearer "+clientToken)

	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(postResp.Body)
		t.Fatalf("Expected 200 OK, got %d: %s", postResp.StatusCode, string(body))
	}

	var mcpResp mcp.Response
	if err := json.NewDecoder(postResp.Body).Decode(&mcpResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if mcpResp.Error != nil {
		t.Fatalf("Unexpected JSON-RPC error: %v", mcpResp.Error)
	}

	// 3. Verify Upstream Credential Stripping:
	// Caller's bearer token was stripped, protocol AuthToken and Custom Header were injected
	authVal := receivedAuth.Load().(string)
	customVal := receivedCustom.Load().(string)

	if authVal == "Bearer "+clientToken {
		t.Errorf("Security violation: Caller token was leaked to upstream: %s", authVal)
	}
	if authVal != "Bearer upstream-bearer-secret" {
		t.Errorf("Expected Authorization 'Bearer upstream-bearer-secret', got '%s'", authVal)
	}
	if customVal != "custom-val-123" {
		t.Errorf("Expected X-Custom-Api-Key 'custom-val-123', got '%s'", customVal)
	}
}
