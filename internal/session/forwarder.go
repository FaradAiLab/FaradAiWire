package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// UpstreamForwarder abstracts reverse-proxying of MCP requests and SSE streams to backend targets.
type UpstreamForwarder interface {
	ForwardMessage(w http.ResponseWriter, r *http.Request, userCtx context.Context, targetURL, targetSessionID, clientSessionID string, body []byte, reqID interface{}, authToken string)
	ForwardDirectSSE(w http.ResponseWriter, r *http.Request, targetURLStr string, onEndpoint func(sessionID, path string))
	ProcessOutgoingMessage(data, clientSessionID, targetURL string) string
	SetBackendPath(path string)
	BackendPath() string
	SetSessionBackendPath(sessionID, path string)
	SessionBackendPath(sessionID string) string
	SetPipeline(p *filter.Pipeline)
	SetCorrelationStore(store CorrelationStore)
	SetHTTPClient(client *http.Client)
}

// Forwarder manages upstream reverse proxying, credential injection, 10MB payload enforcement,
// and response filter pipeline execution for remote MCP endpoints.
type Forwarder struct {
	httpClient       *http.Client
	pipeline         *filter.Pipeline
	correlationStore CorrelationStore
	settingsCache    *settings.Cache
	mu               sync.RWMutex
	backendPath      string
	sessionPaths     map[string]string
}

// NewForwarder initializes a new upstream Forwarder.
func NewForwarder(httpClient *http.Client, pipeline *filter.Pipeline, cStore CorrelationStore) *Forwarder {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 0}
	}
	return &Forwarder{
		httpClient:       httpClient,
		pipeline:         pipeline,
		correlationStore: cStore,
		backendPath:      "/message",
		sessionPaths:     make(map[string]string),
	}
}

// SetPipeline updates the active security filter pipeline.
func (f *Forwarder) SetPipeline(p *filter.Pipeline) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pipeline = p
}

// SetCorrelationStore updates the active correlation store.
func (f *Forwarder) SetCorrelationStore(store CorrelationStore) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.correlationStore = store
}

// SetHTTPClient updates the underlying HTTP transport client.
func (f *Forwarder) SetHTTPClient(client *http.Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if client != nil {
		f.httpClient = client
	}
}

// SetSettingsCache binds the dynamic atomic operational settings cache.
func (f *Forwarder) SetSettingsCache(c *settings.Cache) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settingsCache = c
}

func (f *Forwarder) getMaxPayloadBytes() int64 {
	f.mu.RLock()
	c := f.settingsCache
	f.mu.RUnlock()
	if c != nil {
		if s := c.Get(); s != nil && s.Limits.MaxPayloadBytes > 0 {
			return s.Limits.MaxPayloadBytes
		}
	}
	return 10 << 20 // Default 10MB
}

// SetBackendPath configures the target message path (e.g. "/message").
func (f *Forwarder) SetBackendPath(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.backendPath = strings.TrimSpace(path)
}

// BackendPath returns the currently configured backend message path.
func (f *Forwarder) BackendPath() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.backendPath == "" {
		return "/message"
	}
	return f.backendPath
}

// SetSessionBackendPath associates a specific backend message path with a session.
func (f *Forwarder) SetSessionBackendPath(sessionID, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessionPaths == nil {
		f.sessionPaths = make(map[string]string)
	}
	f.sessionPaths[sessionID] = strings.TrimSpace(path)
}

// SessionBackendPath returns the backend message path for the given session ID,
// falling back to the configured global default path if not specifically set.
func (f *Forwarder) SessionBackendPath(sessionID string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if sessionID != "" && f.sessionPaths != nil {
		if p, ok := f.sessionPaths[sessionID]; ok && p != "" {
			return p
		}
	}
	if f.backendPath == "" {
		return "/message"
	}
	return f.backendPath
}

// ForwardMessage forwards a POST message to the upstream MCP backend, enforcing 10MB payload
// ceilings, header sanitization, trace propagation, and response filter processing.
func (f *Forwarder) ForwardMessage(
	w http.ResponseWriter,
	r *http.Request,
	userCtx context.Context,
	targetURL, targetSessionID, clientSessionID string,
	body []byte,
	reqID interface{},
	authToken string,
) {
	backendBase, err := url.Parse(targetURL)
	if err != nil {
		if reqID != nil {
			errResp := mcp.NewErrorResponse(reqID, -32001, fmt.Sprintf("Upstream corporate gateway unreachable: invalid target URL: %v", err), nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
		http.Error(w, "Invalid target URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	backPath := f.SessionBackendPath(targetSessionID)
	if backPath == "/message" && clientSessionID != "" {
		backPath = f.SessionBackendPath(clientSessionID)
	}
	backendMessageURL := fmt.Sprintf("%s://%s%s", backendBase.Scheme, backendBase.Host, backPath)
	if targetSessionID != "" {
		backendMessageURL = backendMessageURL + "?sessionId=" + url.QueryEscape(targetSessionID)
	} else if r.URL.RawQuery != "" {
		backendMessageURL = backendMessageURL + "?" + r.URL.RawQuery
	}

	backReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, backendMessageURL, bytes.NewBuffer(body))
	if err != nil {
		if reqID != nil {
			errResp := mcp.NewErrorResponse(reqID, -32001, fmt.Sprintf("Upstream corporate gateway unreachable: %v", err), nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sanitizedHeaders := SanitizeUpstreamHeaders(r.Header, authToken)
	for k, vv := range sanitizedHeaders {
		for _, v := range vv {
			backReq.Header.Add(k, v)
		}
	}

	traceID := ""
	if tVal := userCtx.Value(filter.TraceIDContextKey); tVal != nil {
		if t, ok := tVal.(string); ok {
			traceID = t
		}
	}
	if traceID != "" && backReq.Header.Get("X-Trace-ID") == "" {
		backReq.Header.Set("X-Trace-ID", traceID)
	}

	slog.Info("Forwarding message to backend",
		slog.String("target_url", backendMessageURL),
		slog.String("client_session_id", clientSessionID),
		slog.String("trace_id", traceID),
		slog.Int("body_len", len(body)),
	)

	f.mu.RLock()
	client := f.httpClient
	f.mu.RUnlock()

	resp, err := client.Do(backReq)
	if err != nil {
		slog.Warn("Upstream corporate gateway unreachable",
			slog.String("target_url", backendMessageURL),
			slog.String("error", err.Error()),
		)
		if reqID != nil {
			errResp := mcp.NewErrorResponse(reqID, -32001, fmt.Sprintf("Upstream corporate gateway unreachable: %v", err), nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
		http.Error(w, "Failed to connect to backend MCP: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	maxUpstreamBytes := f.getMaxPayloadBytes()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBytes+1))
	if err != nil {
		if reqID != nil {
			errResp := mcp.NewErrorResponse(reqID, -32001, fmt.Sprintf("Upstream corporate gateway unreachable: read response error: %v", err), nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
		http.Error(w, "Failed to read backend response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if int64(len(respBody)) > maxUpstreamBytes {
		slog.Warn("Upstream backend response exceeded payload limit",
			slog.String("target_url", backendMessageURL),
			slog.Int("bytes_read", len(respBody)),
			slog.Int64("max_allowed", maxUpstreamBytes),
		)
		errMsg := fmt.Sprintf("upstream response exceeds %dMB limit", maxUpstreamBytes/(1024*1024))
		if reqID != nil {
			errResp := mcp.NewErrorResponse(reqID, -32603, errMsg, nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	if resp.StatusCode >= 500 && !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		if reqID != nil {
			errResp := mcp.NewErrorResponse(reqID, -32001, fmt.Sprintf("Upstream corporate gateway unreachable: backend returned HTTP %d: %s", resp.StatusCode, string(respBody)), nil)
			respBytes, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
	}

	if len(respBody) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		_, jsonResp, isRequest, parseErr := mcp.ParseMessage(respBody)
		if parseErr == nil && !isRequest && jsonResp != nil {
			var toolName string
			f.mu.RLock()
			cStore := f.correlationStore
			pipeline := f.pipeline
			f.mu.RUnlock()

			if jsonResp.ID != nil && cStore != nil {
				reqIDStr := fmt.Sprintf("%v", jsonResp.ID)
				if pending, ok := cStore.GetAndRemove(NewCorrelationKey(clientSessionID, reqIDStr)); ok && pending != nil {
					toolName = pending.ToolName
				}
			}

			respCtx := userCtx
			if toolName != "" {
				respCtx = context.WithValue(respCtx, filter.ToolNameContextKey, toolName)
			}

			if pipeline != nil {
				filteredResp, mcpErr := pipeline.ProcessResponse(respCtx, jsonResp)
				if mcpErr != nil {
					errResp := mcp.NewErrorResponse(jsonResp.ID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
					respBody, _ = json.Marshal(errResp)
				} else {
					respBody, _ = json.Marshal(filteredResp)
				}
			}
		}
	}

	for k, vv := range resp.Header {
		if k != "Content-Length" {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// ForwardDirectSSE streams Server-Sent Events from an upstream backend directly to the client ResponseWriter.
func (f *Forwarder) ForwardDirectSSE(
	w http.ResponseWriter,
	r *http.Request,
	targetURLStr string,
	onEndpoint func(sessionID, path string),
) {
	backendURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "Invalid target URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clientSessionID := r.URL.Query().Get("sessionId")
	if clientSessionID == "" {
		clientSessionID = r.URL.Query().Get("session_id")
	}
	if clientSessionID == "" {
		clientSessionID = fmt.Sprintf("cl-%d-%x", time.Now().UnixNano(), time.Now().Nanosecond()%0xFFFF)
	}

	q := backendURL.Query()
	for k, vv := range r.URL.Query() {
		for _, v := range vv {
			q.Add(k, v)
		}
	}
	backendURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, backendURL.String(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sanitizedHeaders := SanitizeUpstreamHeaders(r.Header, "")
	for k, vv := range sanitizedHeaders {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	f.mu.RLock()
	client := f.httpClient
	f.mu.RUnlock()

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to connect to backend MCP server: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	reader := bufio.NewReader(resp.Body)
	flusher, _ := w.(http.Flusher)

	var eventName string
	var eventDataBuilder strings.Builder

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			break
		}

		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		if line == "" {
			f.flushEvent(w, flusher, r.Context(), eventName, eventDataBuilder.String(), &clientSessionID, r, targetURLStr, onEndpoint)
			eventName = ""
			eventDataBuilder.Reset()
			continue
		}

		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataVal := strings.TrimPrefix(line, "data:")
			if eventDataBuilder.Len() > 0 {
				eventDataBuilder.WriteString("\n")
			}
			eventDataBuilder.WriteString(strings.TrimSpace(dataVal))
		} else {
			_, _ = w.Write([]byte(line + "\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (f *Forwarder) flushEvent(
	w io.Writer,
	flusher http.Flusher,
	ctx context.Context,
	eventName, data string,
	sessionID *string,
	r *http.Request,
	targetURL string,
	onEndpoint func(sessionID, path string),
) {
	if eventName == "endpoint" {
		cleanData := data
		if idx := strings.Index(data, "?"); idx != -1 {
			cleanData = data[:idx]
		}

		if idx := strings.Index(data, "?"); idx != -1 {
			qStr := data[idx:]
			if u, err := url.Parse(qStr); err == nil {
				realSessionID := u.Query().Get("session_id")
				if realSessionID == "" {
					realSessionID = u.Query().Get("sessionId")
				}
				if realSessionID != "" {
					*sessionID = realSessionID
					if cleanData != "" {
						f.SetSessionBackendPath(realSessionID, cleanData)
					}
					if onEndpoint != nil {
						onEndpoint(realSessionID, cleanData)
					}
				}
			}
		}

		routePrefix := strings.TrimRight(r.URL.Path, "/")
		if routePrefix == "" || routePrefix == "/sse" {
			routePrefix = ""
		}
		rewrittenData := fmt.Sprintf("%s/message%s", routePrefix, extractQueryString(data))
		_, _ = w.Write([]byte(fmt.Sprintf("event: %s\ndata: %s\n\n", eventName, rewrittenData)))
	} else if eventName == "message" {
		sanitizedData := f.ProcessOutgoingMessage(data, *sessionID, targetURL)
		_, _ = w.Write([]byte(fmt.Sprintf("event: %s\ndata: %s\n\n", eventName, sanitizedData)))
	} else {
		if eventName != "" {
			_, _ = w.Write([]byte(fmt.Sprintf("event: %s\ndata: %s\n\n", eventName, data)))
		} else {
			_, _ = w.Write([]byte(fmt.Sprintf("data: %s\n\n", data)))
		}
	}

	if flusher != nil {
		flusher.Flush()
	}
}

// ProcessOutgoingMessage runs an outbound SSE message frame through the response filter pipeline
// using preserved request correlation metadata.
func (f *Forwarder) ProcessOutgoingMessage(data, clientSessionID, targetURL string) string {
	_, jsonResp, isRequest, err := mcp.ParseMessage([]byte(data))
	f.mu.RLock()
	pipeline := f.pipeline
	cStore := f.correlationStore
	f.mu.RUnlock()

	if err != nil || isRequest || jsonResp == nil || pipeline == nil {
		return data
	}

	reqIDStr := fmt.Sprintf("%v", jsonResp.ID)
	var pending *PendingRequest
	if cStore != nil {
		pending, _ = cStore.GetAndRemove(NewCorrelationKey(clientSessionID, reqIDStr))
	}

	userCtx := context.Background()
	if pending != nil && pending.Context != nil {
		userCtx = pending.Context
	}
	if err := userCtx.Err(); err != nil {
		return ""
	}
	if pending != nil {
		if pending.UserCtx != nil {
			userCtx = context.WithValue(userCtx, filter.UserContextKey, pending.UserCtx)
		}
		if pending.TraceID != "" {
			userCtx = context.WithValue(userCtx, filter.TraceIDContextKey, pending.TraceID)
		}
		if pending.ToolName != "" {
			userCtx = context.WithValue(userCtx, filter.ToolNameContextKey, pending.ToolName)
		}
		if pending.AgentName != "" {
			userCtx = context.WithValue(userCtx, filter.AgentNameContextKey, pending.AgentName)
		}
	}

	filteredResp, mcpErr := pipeline.ProcessResponse(userCtx, jsonResp)
	if mcpErr != nil {
		errResp := mcp.NewErrorResponse(jsonResp.ID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
		respBytes, _ := json.Marshal(errResp)
		return string(respBytes)
	}

	respBytes, _ := json.Marshal(filteredResp)
	return string(respBytes)
}

func extractQueryString(urlStr string) string {
	idx := strings.Index(urlStr, "?")
	if idx != -1 {
		return urlStr[idx:]
	}
	return ""
}
