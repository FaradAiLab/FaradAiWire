package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// SSEEvent represents a single Server-Sent Event frame.
type SSEEvent struct {
	Event        string `json:"event"`
	Data         string `json:"data"`
	ProtocolName string `json:"protocol_name,omitempty"`
}

// UpstreamSession maintains the active connection state to an individual MCP backend (HTTP/SSE or stdio subprocess).
type UpstreamSession struct {
	ProtocolID        string             `json:"protocol_id"`
	ProtocolName      string             `json:"protocol_name"`
	URLOrCommand      string             `json:"url_or_command"`
	BackendSessionID  string             `json:"backend_session_id"`
	BackendMessageURL string             `json:"backend_message_url"`
	Type              string             `json:"type"`         // "stdio", "sse", "http"
	TargetScope       string             `json:"target_scope"` // "local", "corporate", "upstream"
	AuthToken         string             `json:"auth_token,omitempty"`
	Headers           map[string]string  `json:"headers,omitempty"`
	Cancel            context.CancelFunc `json:"-"`
	Status             string             `json:"status"` // "READY", "CONNECTING", "DEGRADED", "CLOSED"
	LastPing           time.Time          `json:"last_ping"`
	lastDialStatusCode int
	settingsCache      *settings.Cache
	mu                sync.RWMutex
	closeOnce         sync.Once

	// Local stdio subprocess fields
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	pendingCallsMu sync.Mutex
	pendingCalls   map[string]chan *mcp.Response
	procExitCh     chan struct{}
	procExitOnce   sync.Once
}

// ProcExitCh returns a read-only channel that is closed when the stdio subprocess exits and has been reaped.
func (u *UpstreamSession) ProcExitCh() <-chan struct{} {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.procExitCh
}

// IsHealthy returns true if the upstream session is connected and ready.
func (u *UpstreamSession) IsHealthy() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.Status == "READY"
}

// LastDialStatusCode returns the HTTP status code returned during the last dial attempt (if any).
func (u *UpstreamSession) LastDialStatusCode() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.lastDialStatusCode
}

// SetLastDialStatusCode records the HTTP status code from the dial attempt.
func (u *UpstreamSession) SetLastDialStatusCode(code int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastDialStatusCode = code
}

// SetSettingsCache binds the dynamic atomic operational settings cache.
func (u *UpstreamSession) SetSettingsCache(c *settings.Cache) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.settingsCache = c
}

func (u *UpstreamSession) getMaxPayloadBytes() int64 {
	u.mu.RLock()
	c := u.settingsCache
	u.mu.RUnlock()
	if c != nil {
		if s := c.Get(); s != nil && s.Limits.MaxPayloadBytes > 0 {
			return s.Limits.MaxPayloadBytes
		}
	}
	return 10 << 20 // Default 10MB
}

// IsStdio returns true if the session manages a local stdio subprocess.
func (u *UpstreamSession) IsStdio() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if strings.EqualFold(u.Type, "stdio") {
		return true
	}
	if u.cmd != nil {
		return true
	}
	if u.Type == "" && u.URLOrCommand != "" {
		lower := strings.ToLower(u.URLOrCommand)
		return !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://")
	}
	return false
}

// IsCorporate returns true if the session targets an upstream enterprise gateway.
func (u *UpstreamSession) IsCorporate() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	scope := strings.ToLower(strings.TrimSpace(u.TargetScope))
	return scope == "corporate" || scope == "upstream" || scope == "enterprise"
}

// ErrSubprocessTerminated indicates the child MCP subprocess exited or crashed.
var ErrSubprocessTerminated = fmt.Errorf("mcp subprocess terminated unexpectedly")

// CallTool executes a tool call against a local stdio subprocess synchronously via stdin/stdout.
func (u *UpstreamSession) CallTool(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
	// Reject calls immediately if process has already terminated
	if u.procExitCh != nil {
		select {
		case <-u.procExitCh:
			return nil, ErrSubprocessTerminated
		default:
		}
	}

	u.mu.RLock()
	stdin := u.stdin
	status := u.Status
	u.mu.RUnlock()

	if status == "CLOSED" {
		return nil, ErrSubprocessTerminated
	}

	if stdin == nil || status != "READY" {
		return nil, fmt.Errorf("stdio protocol '%s' is not ready (status: %s)", u.ProtocolName, status)
	}

	reqIDStr := fmt.Sprintf("%v", req.ID)
	respCh := make(chan *mcp.Response, 1)

	u.pendingCallsMu.Lock()
	if u.pendingCalls == nil {
		u.pendingCalls = make(map[string]chan *mcp.Response)
	}
	u.pendingCalls[reqIDStr] = respCh
	u.pendingCallsMu.Unlock()

	defer func() {
		u.pendingCallsMu.Lock()
		delete(u.pendingCalls, reqIDStr)
		u.pendingCallsMu.Unlock()
	}()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON-RPC request: %w", err)
	}

	if u.procExitCh != nil {
		select {
		case <-u.procExitCh:
			return nil, ErrSubprocessTerminated
		default:
		}
	}

	u.mu.Lock()
	if u.stdin == nil {
		u.mu.Unlock()
		return nil, ErrSubprocessTerminated
	}
	_, err = stdin.Write(append(reqBytes, '\n'))
	u.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to write to stdio subprocess: %v", ErrSubprocessTerminated, err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.procExitCh:
		return nil, ErrSubprocessTerminated
	case resp, ok := <-respCh:
		if !ok || resp == nil {
			return nil, ErrSubprocessTerminated
		}
		return resp, nil
	}
}

// IsStreamableHTTP returns true if the session uses Streamable HTTP (direct JSON-RPC POST) transport.
func (u *UpstreamSession) IsStreamableHTTP() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return strings.EqualFold(u.Type, "http") || strings.EqualFold(u.Type, "streamable_http")
}

// CallToolHTTP executes a tool call against a Streamable HTTP backend via direct JSON-RPC POST.
// It injects configured upstream credentials (AuthToken + Headers) and strips client tokens.
func (u *UpstreamSession) CallToolHTTP(ctx context.Context, httpClient *http.Client, req *mcp.Request) (*mcp.Response, error) {
	u.mu.RLock()
	targetURL := u.URLOrCommand
	authToken := u.AuthToken
	headers := u.Headers
	status := u.Status
	u.mu.RUnlock()

	if status == "CLOSED" || status == "DEGRADED" {
		return nil, fmt.Errorf("streamable HTTP protocol '%s' is not ready (status: %s)", u.ProtocolName, status)
	}

	if targetURL == "" {
		return nil, fmt.Errorf("streamable HTTP protocol '%s' has no target URL", u.ProtocolName)
	}

	if httpClient == nil {
		return nil, fmt.Errorf("streamable HTTP protocol '%s' call requires a non-nil http.Client", u.ProtocolName)
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON-RPC request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	// Inject upstream credentials — AuthToken and custom Headers
	if authToken != "" {
		if strings.HasPrefix(strings.ToLower(authToken), "bearer ") {
			httpReq.Header.Set("Authorization", authToken)
		} else {
			httpReq.Header.Set("Authorization", "Bearer "+authToken)
		}
	}
	for k, v := range headers {
		k = strings.TrimSpace(k)
		if k != "" && !IsBlockedUpstreamHeader(k) {
			httpReq.Header.Set(k, v)
		}
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		safeURL := targetURL
		if parsed, pErr := url.Parse(targetURL); pErr == nil {
			safeURL = parsed.Redacted()
		}
		return nil, fmt.Errorf("failed to connect to Streamable HTTP endpoint %s: %w", safeURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Streamable HTTP endpoint returned HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	maxUpstreamBytes := u.getMaxPayloadBytes()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response from Streamable HTTP endpoint: %w", err)
	}

	if int64(len(body)) > maxUpstreamBytes {
		return nil, fmt.Errorf("Streamable HTTP response exceeded %dMB payload limit", maxUpstreamBytes/(1024*1024))
	}

	// Handle SSE-wrapped responses (Content-Type: text/event-stream with "data:" prefix)
	body = extractJSONFromSSEOrDirect(body)

	var rpcResp mcp.Response
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response from Streamable HTTP endpoint: %w", err)
	}

	// Update last ping
	u.mu.Lock()
	u.LastPing = time.Now()
	u.mu.Unlock()

	return &rpcResp, nil
}

// extractJSONFromSSEOrDirect handles responses that may be either plain JSON or
// SSE-wrapped (text/event-stream with multi-line "data:" prefix chunks).
func extractJSONFromSSEOrDirect(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return trimmed
	}

	var dataLines []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data:"))
		}
	}
	if len(dataLines) > 0 {
		combined := strings.TrimSpace(strings.Join(dataLines, "\n"))
		if len(combined) > 0 && (combined[0] == '{' || combined[0] == '[') {
			return []byte(combined)
		}
	}
	return trimmed
}

// CloseStdin closes the stdio subprocess's stdin pipe to signal EOF to the child.
func (u *UpstreamSession) CloseStdin() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stdin != nil {
		_ = u.stdin.Close()
		u.stdin = nil
	}
}

// SendNotification writes a notification or raw message to the stdio subprocess stdin.
func (u *UpstreamSession) SendNotification(data []byte) error {
	if u.procExitCh != nil {
		select {
		case <-u.procExitCh:
			return ErrSubprocessTerminated
		default:
		}
	}

	u.mu.RLock()
	stdin := u.stdin
	status := u.Status
	u.mu.RUnlock()

	if status == "CLOSED" {
		return ErrSubprocessTerminated
	}

	if stdin == nil || status != "READY" {
		return fmt.Errorf("stdio protocol '%s' is not ready (status: %s)", u.ProtocolName, status)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.stdin == nil {
		return ErrSubprocessTerminated
	}

	if _, err := u.stdin.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("%w: %v", ErrSubprocessTerminated, err)
	}

	return nil
}

// GetBackendSessionID safely gets the backend session identifier.
func (u *UpstreamSession) GetBackendSessionID() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.BackendSessionID
}

// SetBackendSessionID safely updates the backend session identifier.
func (u *UpstreamSession) SetBackendSessionID(id string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.BackendSessionID = id
}

// GetBackendMessageURL safely gets the upstream message POST URL.
func (u *UpstreamSession) GetBackendMessageURL() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.BackendMessageURL
}

// GetHeaders safely returns a copy of configured custom upstream headers.
func (u *UpstreamSession) GetHeaders() map[string]string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Headers == nil {
		return nil
	}
	cp := make(map[string]string, len(u.Headers))
	for k, v := range u.Headers {
		cp[k] = v
	}
	return cp
}

// SetBackendMessageURL safely updates the upstream message POST URL.
func (u *UpstreamSession) SetBackendMessageURL(msgURL string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.BackendMessageURL = msgURL
}

// GetStatus safely returns the session status.
func (u *UpstreamSession) GetStatus() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.Status
}

// SetStatus safely updates the session status.
func (u *UpstreamSession) SetStatus(status string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Status = status
}

// Close terminates the upstream connection, canceling its context, closing stdin, and reaping process groups if stdio.
// Safe for concurrent and repeated calls via sync.Once.
func (u *UpstreamSession) Close() {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		cancel := u.Cancel
		stdin := u.stdin
		cmd := u.cmd
		procExitCh := u.procExitCh
		u.Status = "CLOSED"
		u.stdin = nil
		u.mu.Unlock()

		if stdin != nil {
			_ = stdin.Close()
		}
		if cmd != nil {
			killProcessGroup(cmd, procExitCh)
		}
		if cancel != nil {
			cancel()
		}
	})
}

// AgentSessionBridge represents a client's unified SSE connection multiplexing multiple upstream MCP sessions.
type AgentSessionBridge struct {
	ClientSessionID string                      `json:"client_session_id"`
	AgentName       string                      `json:"agent_name"`
	Upstreams       map[string]*UpstreamSession `json:"upstreams"`  // canonical protocol_id -> UpstreamSession
	NameToID        map[string]string           `json:"name_to_id"` // protocol_name -> protocol_id
	EventCh         chan SSEEvent               `json:"-"`
	Cancel          context.CancelFunc          `json:"-"`
	BridgeCtx       context.Context             `json:"-"`
	CreatedAt       time.Time                   `json:"created_at"`
	LastActive      time.Time                   `json:"last_active"`
	mu              sync.RWMutex
}

// Touch updates the last active timestamp to prevent idle eviction.
func (b *AgentSessionBridge) Touch() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.LastActive = time.Now()
}

// SetLastActive sets the last active timestamp safely under the bridge mutex.
func (b *AgentSessionBridge) SetLastActive(t time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.LastActive = t
}

// GetUpstream safely retrieves an upstream session by canonical protocol ID or protocol name alias.
func (b *AgentSessionBridge) GetUpstream(nameOrID string) *UpstreamSession {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 1. Direct canonical protocol ID or key lookup
	if up, ok := b.Upstreams[nameOrID]; ok {
		return up
	}

	// 2. Protocol name alias lookup
	if b.NameToID != nil {
		if id, ok := b.NameToID[nameOrID]; ok {
			if up, ok := b.Upstreams[id]; ok {
				return up
			}
		}
	}

	return nil
}

// SetUpstream safely associates an upstream session with the given key.
func (b *AgentSessionBridge) SetUpstream(key string, up *UpstreamSession) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Upstreams == nil {
		b.Upstreams = make(map[string]*UpstreamSession)
	}
	b.Upstreams[key] = up
}

// RegisterAlias maps a protocol name to a canonical protocol ID.
func (b *AgentSessionBridge) RegisterAlias(name, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.NameToID == nil {
		b.NameToID = make(map[string]string)
	}
	b.NameToID[name] = id
}

// SetUpstreamWithAlias associates an upstream session by canonical ID and registers a name alias.
func (b *AgentSessionBridge) SetUpstreamWithAlias(id, name string, up *UpstreamSession) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Upstreams == nil {
		b.Upstreams = make(map[string]*UpstreamSession)
	}
	canonicalKey := id
	if canonicalKey == "" {
		canonicalKey = name
	}
	if canonicalKey != "" {
		b.Upstreams[canonicalKey] = up
	}
	if name != "" && id != "" {
		if b.NameToID == nil {
			b.NameToID = make(map[string]string)
		}
		b.NameToID[name] = id
	}
}

// BroadcastShutdownEvent sends an SSE shutdown frame to the client without terminating upstreams or canceling bridge context.
func (b *AgentSessionBridge) BroadcastShutdownEvent() {
	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case b.EventCh <- SSEEvent{
		Event: "shutdown",
		Data:  `{"code":"GATEWAY_DRAINING","message":"Server shutting down. Reconnect to alternate instance."}`,
	}:
	default:
	}
}

// BroadcastShutdown sends an SSE shutdown frame to the client, cancels the bridge context, and terminates upstreams.
func (b *AgentSessionBridge) BroadcastShutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Send shutdown frame non-blockingly so client receives clean eviction
	select {
	case b.EventCh <- SSEEvent{
		Event: "shutdown",
		Data:  `{"code":"GATEWAY_DRAINING","message":"Server shutting down. Reconnect to alternate instance."}`,
	}:
	default:
	}

	// 2. Cancel bridge context to immediately unblock the HTTP streaming handler
	if b.Cancel != nil {
		b.Cancel()
	}

	// 3. Terminate all attached upstreams uniquely (guaranteed no double close)
	closed := make(map[*UpstreamSession]struct{}, len(b.Upstreams))
	for _, up := range b.Upstreams {
		if up == nil {
			continue
		}
		if _, alreadyClosed := closed[up]; alreadyClosed {
			continue
		}
		closed[up] = struct{}{}
		up.Close()
	}
}

// Close terminates all upstream connections and cancels the bridge context.
func (b *AgentSessionBridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.Cancel != nil {
		b.Cancel()
	}

	closed := make(map[*UpstreamSession]struct{}, len(b.Upstreams))
	for _, up := range b.Upstreams {
		if up == nil {
			continue
		}
		if _, alreadyClosed := closed[up]; alreadyClosed {
			continue
		}
		closed[up] = struct{}{}
		up.Close()
	}
}
