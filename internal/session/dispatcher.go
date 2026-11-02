package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// ToolExecutionResult captures the routing target for proxying or the final response if executed locally.
type ToolExecutionResult struct {
	ExecutedLocally bool
	Response        *mcp.Response
	TargetURL       string
	TargetSessionID string
	AuthToken       string
	RawToolName     string
}

// ToolDispatcher abstracts tool routing and execution across local stdio and remote HTTP/SSE transports.
type ToolDispatcher interface {
	DispatchTool(ctx context.Context, agentName, toolName string, req *mcp.Request, headers http.Header, bridge *AgentSessionBridge) (*ToolExecutionResult, error)
}

// SessionToolDispatcher implements ToolDispatcher for routing and executing tool calls.
type SessionToolDispatcher struct {
	repo          agent.Resolver
	mgr           *Manager
	httpClient    *http.Client
	settingsCache *settings.Cache
	mu            sync.RWMutex
}

// NewToolDispatcher creates a new SessionToolDispatcher.
func NewToolDispatcher(repo agent.Resolver, mgr *Manager) *SessionToolDispatcher {
	return &SessionToolDispatcher{
		repo:       repo,
		mgr:        mgr,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// SetHTTPClient sets the HTTP client used for Streamable HTTP tool calls.
func (d *SessionToolDispatcher) SetHTTPClient(client *http.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if client != nil {
		d.httpClient = client
	}
}

// SetSettingsCache binds the dynamic atomic operational settings cache.
func (d *SessionToolDispatcher) SetSettingsCache(c *settings.Cache) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.settingsCache = c
}

func (d *SessionToolDispatcher) getHTTPClient() *http.Client {
	d.mu.RLock()
	c := d.settingsCache
	baseClient := d.httpClient
	d.mu.RUnlock()

	timeout := 60 * time.Second
	if c != nil {
		if s := c.Get(); s != nil && s.Timeouts.ToolExecutionTimeoutSec > 0 {
			timeout = time.Duration(s.Timeouts.ToolExecutionTimeoutSec) * time.Second
		}
	}
	if baseClient != nil && baseClient.Timeout == timeout {
		return baseClient
	}
	if baseClient == nil {
		return &http.Client{Timeout: timeout}
	}
	cloned := *baseClient
	cloned.Timeout = timeout
	return &cloned
}

// DispatchTool resolves target protocols and executes local stdio tools or provides routing for remote endpoints.
func (d *SessionToolDispatcher) DispatchTool(ctx context.Context, agentName, toolName string, req *mcp.Request, headers http.Header, bridge *AgentSessionBridge) (*ToolExecutionResult, error) {
	if agentName == "" && bridge != nil {
		agentName = bridge.AgentName
	}

	if d.repo == nil {
		return &ToolExecutionResult{ExecutedLocally: false}, nil
	}

	toolInfo, _ := d.repo.ResolveToolProtocol(agentName, toolName)
	if toolInfo == nil {
		return &ToolExecutionResult{ExecutedLocally: false}, nil
	}

	// Dual-layer zero-trust: intercept unapproved tool invocations with -32004 security error
	if !toolInfo.IsToolAllowed(toolName) {
		var reqID interface{}
		if req != nil {
			reqID = req.ID
		}
		errResp := mcp.NewErrorResponse(reqID, -32004, fmt.Sprintf("Security policy violation: Tool '%s' is not allowed by protocol whitelist", toolName), map[string]interface{}{
			"agent":    agentName,
			"protocol": toolInfo.ProtocolName,
			"tool":     toolName,
		})
		return &ToolExecutionResult{
			ExecutedLocally: true,
			Response:        errResp,
		}, nil
	}

	if agentCfg, _ := d.repo.GetAgentConfig(agentName); agentCfg != nil {
		if !agentCfg.IsToolAllowed(toolName) {
			var reqID interface{}
			if req != nil {
				reqID = req.ID
			}
			errResp := mcp.NewErrorResponse(reqID, -32004, fmt.Sprintf("Security policy violation: Tool '%s' is not allowed by agent tool scoping policy", toolName), map[string]interface{}{
				"agent": agentName,
				"tool":  toolName,
			})
			return &ToolExecutionResult{
				ExecutedLocally: true,
				Response:        errResp,
			}, nil
		}
	}

	targetURL := toolInfo.TargetURL
	authToken := toolInfo.AuthToken
	targetSessionID := ""

	var upSess *UpstreamSession
	if bridge != nil {
		upSess = bridge.GetUpstream(toolInfo.ProtocolID)
		if upSess == nil {
			upSess = bridge.GetUpstream(toolInfo.ProtocolName)
		}
	}

	// JIT Reconnect if needed
	// Streamable HTTP sessions are stateless — they don't have a BackendSessionID
	needsReconnect := upSess == nil || !upSess.IsHealthy()
	if !needsReconnect && upSess != nil && !upSess.IsStdio() && !upSess.IsStreamableHTTP() && upSess.GetBackendSessionID() == "" {
		needsReconnect = true
	}
	if needsReconnect {
		if agentCfg, _ := d.repo.GetAgentConfig(agentName); agentCfg != nil && bridge != nil && d.mgr != nil {
			proto := agentCfg.FindProtocol(toolInfo.ProtocolName)
			if proto == nil {
				proto = agentCfg.FindProtocol(toolInfo.ProtocolID)
			}
			if proto != nil {
				reconnected, recErr := d.mgr.GetOrDialUpstream(ctx, bridge, *proto, headers)
				if recErr == nil && reconnected != nil && reconnected.IsHealthy() {
					upSess = reconnected
					if !upSess.IsStdio() {
						targetSessionID = reconnected.GetBackendSessionID()
						targetURL = reconnected.URLOrCommand
					}
				}
			}
		}
	} else if !upSess.IsStdio() && !upSess.IsStreamableHTTP() {
		targetSessionID = upSess.GetBackendSessionID()
	}

	if upSess != nil && upSess.AuthToken != "" && authToken == "" {
		authToken = upSess.AuthToken
	}

	rawToolName := toolInfo.RawToolName
	if rawToolName == "" {
		if strings.Contains(toolName, "__") {
			parts := strings.SplitN(toolName, "__", 2)
			rawToolName = parts[1]
		} else {
			rawToolName = toolName
		}
	}

	// Streamable HTTP tool execution via direct JSON-RPC POST (Zero-Sniffing-Penalty)
	if (toolInfo.IsStreamableHTTP() || (upSess != nil && upSess.IsStreamableHTTP())) && req != nil && req.Method == "tools/call" {
		if upSess == nil || !upSess.IsHealthy() {
			errResp := mcp.NewErrorResponse(req.ID, mcp.ErrInternalError, fmt.Sprintf("Streamable HTTP protocol '%s' is unavailable", toolInfo.ProtocolName), nil)
			return &ToolExecutionResult{
				ExecutedLocally: true,
				Response:        errResp,
			}, nil
		}

		upstreamReq := req
		if rawToolName != "" && rawToolName != toolName {
			upstreamReq = rewriteToolCallRequest(req, rawToolName)
		}

		if d.settingsCache != nil {
			upSess.SetSettingsCache(d.settingsCache)
		}
		resp, execErr := upSess.CallToolHTTP(ctx, d.getHTTPClient(), upstreamReq)
		if execErr != nil {
			errResp := mcp.NewErrorResponse(req.ID, mcp.ErrInternalError, fmt.Sprintf("Streamable HTTP tool execution failed: %v", execErr), nil)
			return &ToolExecutionResult{
				ExecutedLocally: true,
				Response:        errResp,
			}, nil
		}

		return &ToolExecutionResult{
			ExecutedLocally: true,
			Response:        resp,
		}, nil
	}

	// Local tool execution via stdio subprocess (Zero-Egress Invariant)
	if (toolInfo.IsStdio() || (upSess != nil && upSess.IsStdio())) && req != nil && req.Method == "tools/call" {
		if upSess == nil || !upSess.IsHealthy() {
			errResp := mcp.NewErrorResponse(req.ID, mcp.ErrInternalError, fmt.Sprintf("Local stdio protocol '%s' is unavailable", toolInfo.ProtocolName), nil)
			return &ToolExecutionResult{
				ExecutedLocally: true,
				Response:        errResp,
			}, nil
		}

		upstreamReq := req
		if rawToolName != "" && rawToolName != toolName {
			upstreamReq = rewriteToolCallRequest(req, rawToolName)
		}

		resp, execErr := upSess.CallTool(ctx, upstreamReq)
		if execErr != nil {
			errResp := mcp.NewErrorResponse(req.ID, mcp.ErrInternalError, fmt.Sprintf("Local tool execution failed: %v", execErr), nil)
			return &ToolExecutionResult{
				ExecutedLocally: true,
				Response:        errResp,
			}, nil
		}

		return &ToolExecutionResult{
			ExecutedLocally: true,
			Response:        resp,
		}, nil
	}

	return &ToolExecutionResult{
		ExecutedLocally: false,
		TargetURL:       targetURL,
		TargetSessionID: targetSessionID,
		AuthToken:       authToken,
		RawToolName:     rawToolName,
	}, nil
}

// rewriteToolCallRequest creates a clone of req with Params.name rewritten to rawToolName.
func rewriteToolCallRequest(req *mcp.Request, rawToolName string) *mcp.Request {
	if req == nil || rawToolName == "" || len(req.Params) == 0 {
		return req
	}
	var paramsMap map[string]interface{}
	if err := json.Unmarshal(req.Params, &paramsMap); err != nil {
		return req
	}
	paramsMap["name"] = rawToolName
	newParams, err := json.Marshal(paramsMap)
	if err != nil {
		return req
	}
	cloned := *req
	cloned.Params = newParams
	return &cloned
}

