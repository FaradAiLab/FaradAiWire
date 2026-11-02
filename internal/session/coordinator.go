package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// InboundCoordinator coordinates message decoding, security filter pipeline execution,
// manifest aggregation, tool dispatching (local stdio vs remote), and upstream forwarding.
type InboundCoordinator struct {
	pipeline           *filter.Pipeline
	agentRepo          agent.Resolver
	sessionMgr         *Manager
	manifestAggregator agent.ManifestAggregator
	toolDispatcher     ToolDispatcher
	correlationStore   CorrelationStore
	forwarder          UpstreamForwarder
	defaultTargetURL   string
	mu                 sync.RWMutex
}

// NewInboundCoordinator creates a new InboundCoordinator with all required services.
func NewInboundCoordinator(
	pipeline *filter.Pipeline,
	agentRepo agent.Resolver,
	sessionMgr *Manager,
	manifestAggregator agent.ManifestAggregator,
	toolDispatcher ToolDispatcher,
	correlationStore CorrelationStore,
	forwarder UpstreamForwarder,
	defaultTargetURL string,
) *InboundCoordinator {
	return &InboundCoordinator{
		pipeline:           pipeline,
		agentRepo:          agentRepo,
		sessionMgr:         sessionMgr,
		manifestAggregator: manifestAggregator,
		toolDispatcher:     toolDispatcher,
		correlationStore:   correlationStore,
		forwarder:          forwarder,
		defaultTargetURL:   defaultTargetURL,
	}
}

// SetPipeline updates the active security filter pipeline.
func (c *InboundCoordinator) SetPipeline(p *filter.Pipeline) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pipeline = p
}

// SetAgentRepository updates the agent repository and default aggregator/dispatcher.
func (c *InboundCoordinator) SetAgentRepository(repo agent.Resolver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agentRepo = repo
	c.manifestAggregator = agent.NewManifestAggregator(repo)
	if c.sessionMgr == nil && repo != nil {
		c.sessionMgr = NewManager(repo, nil)
	}
	if c.sessionMgr != nil {
		c.toolDispatcher = NewToolDispatcher(repo, c.sessionMgr)
	}
}

// SetSessionManager updates the active session manager.
func (c *InboundCoordinator) SetSessionManager(mgr *Manager) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionMgr = mgr
	if c.agentRepo != nil {
		c.toolDispatcher = NewToolDispatcher(c.agentRepo, mgr)
	}
}

// SetToolDispatcher configures a custom tool dispatcher.
func (c *InboundCoordinator) SetToolDispatcher(dispatcher ToolDispatcher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.toolDispatcher = dispatcher
}

// SetManifestAggregator configures a custom manifest aggregator.
func (c *InboundCoordinator) SetManifestAggregator(agg agent.ManifestAggregator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifestAggregator = agg
}

// SetCorrelationStore configures the correlation store.
func (c *InboundCoordinator) SetCorrelationStore(store CorrelationStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.correlationStore = store
}

// SetForwarder configures the upstream forwarder.
func (c *InboundCoordinator) SetForwarder(f UpstreamForwarder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forwarder = f
}

// Pipeline returns the active security filter pipeline.
func (c *InboundCoordinator) Pipeline() *filter.Pipeline {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pipeline
}

// AgentRepository returns the active agent resolver.
func (c *InboundCoordinator) AgentRepository() agent.Resolver {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.agentRepo
}

// SessionManager returns the active session manager.
func (c *InboundCoordinator) SessionManager() *Manager {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionMgr
}

// Forwarder returns the active upstream forwarder.
func (c *InboundCoordinator) Forwarder() UpstreamForwarder {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.forwarder
}

// CorrelationStore returns the active correlation store.
func (c *InboundCoordinator) CorrelationStore() CorrelationStore {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.correlationStore
}

// ManifestAggregator returns the active manifest aggregator.
func (c *InboundCoordinator) ManifestAggregator() agent.ManifestAggregator {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.manifestAggregator
}

// ToolDispatcher returns the active tool dispatcher.
func (c *InboundCoordinator) ToolDispatcher() ToolDispatcher {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.toolDispatcher
}

// ExecuteMessage coordinates request authentication verification, in-flight correlation tracking,
// filter pipeline execution, tools/list synthesis, local tool execution, and upstream forwarding.
func (c *InboundCoordinator) ExecuteMessage(
	w http.ResponseWriter,
	r *http.Request,
	userCtx context.Context,
	clientSessionID string,
	agentName string,
	body []byte,
	req *mcp.Request,
	sessionTargetResolver func(sessionID string) (string, bool),
) {
	c.mu.RLock()
	pipeline := c.pipeline
	agentRepo := c.agentRepo
	sessionMgr := c.sessionMgr
	aggregator := c.manifestAggregator
	dispatcher := c.toolDispatcher
	cStore := c.correlationStore
	forwarder := c.forwarder
	defaultTargetURL := c.defaultTargetURL
	c.mu.RUnlock()

	var bridge *AgentSessionBridge
	var hasBridge bool
	if sessionMgr != nil {
		bridge, hasBridge = sessionMgr.GetBridge(clientSessionID)
	}
	if hasBridge && bridge != nil {
		if agentName == "" && bridge.AgentName != "" {
			agentName = bridge.AgentName
			userCtx = context.WithValue(userCtx, filter.AgentNameContextKey, agentName)
		}
	}

	isRequest := (req != nil)
	traceID := ""
	if tVal := userCtx.Value(filter.TraceIDContextKey); tVal != nil {
		if t, ok := tVal.(string); ok {
			traceID = t
		}
	}

	if isRequest {
		var toolName string
		if req.Method == "tools/call" {
			var callParams struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(req.Params, &callParams); err == nil {
				toolName = callParams.Name
			}
		}

		if req.ID != nil && cStore != nil {
			reqIDStr := fmt.Sprintf("%v", req.ID)
			var uCtx *filter.UserContext
			if uVal := userCtx.Value(filter.UserContextKey); uVal != nil {
				if u, ok := uVal.(*filter.UserContext); ok {
					uCtx = u
				}
			}
			cStore.Put(NewCorrelationKey(clientSessionID, reqIDStr), &PendingRequest{
				UserCtx:   uCtx,
				Context:   r.Context(),
				ToolName:  toolName,
				AgentName: agentName,
				Timestamp: time.Now(),
				TraceID:   traceID,
			})
		}

		var origParams []byte
		if req != nil && len(req.Params) > 0 {
			origParams = bytes.Clone(req.Params)
		}

		if pipeline != nil {
			finalReq, mcpErr := pipeline.ProcessRequest(userCtx, req)
			if mcpErr != nil {
				resp := mcp.NewErrorResponse(req.ID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
				respBytes, _ := json.Marshal(resp)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(respBytes)

				if req.ID != nil && cStore != nil {
					reqIDStr := fmt.Sprintf("%v", req.ID)
					cStore.Remove(NewCorrelationKey(clientSessionID, reqIDStr))
				}
				return
			}
			if finalReq != nil {
				req = finalReq
				if len(req.Params) > 0 && (len(origParams) == 0 || !bytes.Equal(origParams, req.Params)) {
					body = syncRequestBodyWithParams(body, req.Params)
				}
			}
		}

		// MCP protocol lifecycle: initialize
		if req.Method == "initialize" {
			effectiveAgent := agentName
			if effectiveAgent == "" && bridge != nil {
				effectiveAgent = bridge.AgentName
			}
			serverName := "farad-ai-wire"
			if effectiveAgent != "" {
				serverName = fmt.Sprintf("farad-ai-%s", effectiveAgent)
			}
			resultBytes, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{
						"listChanged": false,
					},
				},
				"serverInfo": map[string]interface{}{
					"name":    serverName,
					"version": "1.0.0",
				},
			})
			jsonResp := &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  resultBytes,
			}
			respBytes, _ := json.Marshal(jsonResp)
			if clientSessionID != "" {
				w.Header().Set("Mcp-Session-Id", clientSessionID)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}

		// MCP protocol lifecycle: notifications (e.g. notifications/initialized)
		if req.Method == "notifications/initialized" || strings.HasPrefix(req.Method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// MCP protocol lifecycle: ping
		if req.Method == "ping" && (agentName != "" || bridge != nil) {
			jsonResp := &mcp.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  json.RawMessage(`{}`),
			}
			respBytes, _ := json.Marshal(jsonResp)
			if clientSessionID != "" {
				w.Header().Set("Mcp-Session-Id", clientSessionID)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}

		// Aggregated tools/list handling via ManifestAggregator
		if req.Method == "tools/list" && aggregator != nil {
			targetAgent := agentName
			if targetAgent == "" && bridge != nil {
				targetAgent = bridge.AgentName
			}
			toolsList, aggErr := aggregator.CompileToolsList(r.Context(), targetAgent)
			if aggErr == nil && len(toolsList) > 0 {
				resultBytes, _ := json.Marshal(map[string]interface{}{
					"tools": toolsList,
				})
				jsonResp := &mcp.Response{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  resultBytes,
				}

				respCtx := userCtx
				if targetAgent != "" {
					respCtx = context.WithValue(respCtx, filter.AgentNameContextKey, targetAgent)
				}

				var filteredResp *mcp.Response = jsonResp
				if pipeline != nil {
					var mcpErr *mcp.Error
					filteredResp, mcpErr = pipeline.ProcessResponse(respCtx, jsonResp)
					if mcpErr != nil {
						errResp := mcp.NewErrorResponse(req.ID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
						respBytes, _ := json.Marshal(errResp)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(respBytes)
						return
					}
				}
				respBytes, _ := json.Marshal(filteredResp)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(respBytes)
				return
			}
		}
	}

	targetURL := defaultTargetURL
	targetSessionID := ""
	var authToken string
	var dispatchRes *ToolExecutionResult

	var toolName string
	if isRequest && req != nil && req.Method == "tools/call" {
		var callParams struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err == nil {
			toolName = callParams.Name
		}
	}

	if bridge != nil && dispatcher != nil {
		if isRequest && req.Method == "tools/call" {
			// Dual-layer zero-trust: intercept unapproved tool invocations with -32004 security error
			effectiveAgent := agentName
			if effectiveAgent == "" && bridge != nil {
				effectiveAgent = bridge.AgentName
			}
			if toolName != "" && c.agentRepo != nil && effectiveAgent != "" {
				toolInfo, _ := c.agentRepo.ResolveToolProtocol(effectiveAgent, toolName)
				if toolInfo != nil && !toolInfo.IsToolAllowed(toolName) {
					var reqID interface{}
					if req != nil {
						reqID = req.ID
					}
					errResp := mcp.NewErrorResponse(reqID, -32004, fmt.Sprintf("Security policy violation: Tool '%s' is not allowed by protocol whitelist", toolName), map[string]interface{}{
						"agent":    effectiveAgent,
						"protocol": toolInfo.ProtocolName,
						"tool":     toolName,
					})
					respBytes, _ := json.Marshal(errResp)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(respBytes)
					return
				}

				agentCfg, _ := c.agentRepo.GetAgentConfig(effectiveAgent)
				if agentCfg != nil && !agentCfg.IsToolAllowed(toolName) {
					var reqID interface{}
					if req != nil {
						reqID = req.ID
					}
					errResp := mcp.NewErrorResponse(reqID, -32004, fmt.Sprintf("Security policy violation: Tool '%s' is not allowed by agent tool scoping policy", toolName), map[string]interface{}{
						"agent": effectiveAgent,
						"tool":  toolName,
					})
					respBytes, _ := json.Marshal(errResp)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(respBytes)
					return
				}
			}
		}

		var dispatchErr error
		dispatchRes, dispatchErr = dispatcher.DispatchTool(userCtx, bridge.AgentName, toolName, req, r.Header, bridge)
		if dispatchErr != nil {
			var reqID interface{}
			if req != nil {
				reqID = req.ID
			}
			errResp := mcp.NewErrorResponse(reqID, mcp.ErrInternalError, dispatchErr.Error(), nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(respBytes)
			return
		}

		if dispatchRes != nil {
			if dispatchRes.ExecutedLocally {
				resp := dispatchRes.Response
				respCtx := userCtx
				if toolName != "" {
					respCtx = context.WithValue(respCtx, filter.ToolNameContextKey, toolName)
				}
				if bridge.AgentName != "" {
					respCtx = context.WithValue(respCtx, filter.AgentNameContextKey, bridge.AgentName)
				}

				var filteredResp *mcp.Response = resp
				if pipeline != nil {
					var mcpErr *mcp.Error
					filteredResp, mcpErr = pipeline.ProcessResponse(respCtx, resp)
					if mcpErr != nil {
						var reqID interface{}
						if req != nil {
							reqID = req.ID
						}
						errResp := mcp.NewErrorResponse(reqID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
						respBytes, _ := json.Marshal(errResp)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(respBytes)
						return
					}
				}

				if req != nil && req.ID != nil && cStore != nil {
					reqIDStr := fmt.Sprintf("%v", req.ID)
					cStore.Remove(NewCorrelationKey(clientSessionID, reqIDStr))
				}

				respBytes, _ := json.Marshal(filteredResp)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(respBytes)
				return
			}

			if dispatchRes.TargetURL != "" {
				targetURL = dispatchRes.TargetURL
			}
			if dispatchRes.TargetSessionID != "" && !strings.HasPrefix(r.URL.Path, "/mcp") {
				targetSessionID = dispatchRes.TargetSessionID
			}
			if dispatchRes.AuthToken != "" {
				authToken = dispatchRes.AuthToken
			}
		}

		if targetURL == defaultTargetURL && targetSessionID == "" {
			bridge.Touch()
			for _, pName := range []string{"primary", "default"} {
				if up := bridge.GetUpstream(pName); up != nil && up.IsHealthy() {
					targetURL = up.URLOrCommand
					if !strings.HasPrefix(r.URL.Path, "/mcp") {
						targetSessionID = up.GetBackendSessionID()
					}
					authToken = up.AuthToken
					break
				}
			}
		}
	} else if reqPath := strings.TrimRight(r.URL.Path, "/"); (strings.HasPrefix(reqPath, "/sse/") || strings.HasPrefix(reqPath, "/mcp/")) && agentRepo != nil {
		basePath := reqPath
		if strings.HasPrefix(reqPath, "/mcp/") {
			basePath = "/sse/" + strings.TrimPrefix(reqPath, "/mcp/")
		}
		basePath = strings.TrimSuffix(basePath, "/message")
		basePath = strings.TrimSuffix(basePath, "/mcp")
		if resolved, err := agentRepo.ResolveTargetURLFromPath(basePath, defaultTargetURL); err == nil && resolved != "" {
			targetURL = resolved
		}
	} else if clientSessionID != "" && sessionTargetResolver != nil {
		if boundURL, ok := sessionTargetResolver(clientSessionID); ok && boundURL != "" {
			targetURL = boundURL
		}
	}

	if targetURL == "" {
		targetURL = defaultTargetURL
	}

	if isRequest && req != nil && req.Method == "tools/call" {
		rawToolName := ""
		if dispatchRes != nil && dispatchRes.RawToolName != "" {
			rawToolName = dispatchRes.RawToolName
		} else if strings.Contains(toolName, "__") {
			parts := strings.SplitN(toolName, "__", 2)
			rawToolName = parts[1]
		}
		if rawToolName != "" && rawToolName != toolName {
			body = rewriteToolCallBody(body, rawToolName)
		}
	}

	var reqID interface{}
	if req != nil {
		reqID = req.ID
	}

	if forwarder != nil {
		forwarder.ForwardMessage(w, r, userCtx, targetURL, targetSessionID, clientSessionID, body, reqID, authToken)
	} else {
		http.Error(w, "upstream forwarder not configured", http.StatusInternalServerError)
	}
}

// rewriteToolCallBody rewrites the "params.name" field in the JSON-RPC body to rawToolName.
func rewriteToolCallBody(body []byte, rawToolName string) []byte {
	if len(body) == 0 || rawToolName == "" {
		return body
	}
	var reqMap map[string]interface{}
	if err := json.Unmarshal(body, &reqMap); err != nil {
		return body
	}
	if method, _ := reqMap["method"].(string); method != "tools/call" {
		return body
	}
	params, ok := reqMap["params"].(map[string]interface{})
	if !ok || params == nil {
		return body
	}
	params["name"] = rawToolName
	reqMap["params"] = params
	newBody, err := json.Marshal(reqMap)
	if err != nil {
		return body
	}
	return newBody
}

// syncRequestBodyWithParams replaces the "params" field in body with newParams while preserving other fields.
func syncRequestBodyWithParams(body []byte, newParams []byte) []byte {
	if len(body) == 0 || len(newParams) == 0 {
		return body
	}
	var reqMap map[string]interface{}
	if err := json.Unmarshal(body, &reqMap); err != nil {
		return body
	}
	reqMap["params"] = json.RawMessage(newParams)
	newBody, err := json.Marshal(reqMap)
	if err != nil {
		return body
	}
	return newBody
}
