package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

// safeBuffer provides a thread-safe bytes.Buffer wrapper for concurrent subprocess stdio.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// UpstreamHTTPError represents a structured diagnostic error returned when an upstream MCP server
// responds with a non-200 HTTP status code during probing. It carries the exact status code,
// error category, and a human-readable remediation message so the frontend can render actionable guidance.
type UpstreamHTTPError struct {
	StatusCode  int    `json:"status_code"`
	Category    string `json:"category"`
	Remediation string `json:"remediation"`
}

func (e *UpstreamHTTPError) Error() string {
	return fmt.Sprintf("HTTP %d %s from upstream: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Remediation)
}

// upstreamHTTPRemediation returns a user-facing remediation message for common HTTP error status codes.
func upstreamHTTPRemediation(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized: // 401
		return "Remote server rejected credentials. Verify your Authentication Token or add the required API key header."
	case http.StatusForbidden: // 403
		return "Access denied by remote server. Check that your credentials have sufficient permissions or the IP allowlist includes this Gateway."
	case http.StatusNotFound: // 404
		return "Endpoint not found. Verify the URL path is correct and the MCP server is deployed at this address."
	case http.StatusMethodNotAllowed: // 405
		return "Server does not accept this HTTP method. The endpoint may use Streamable HTTP (POST) instead of legacy SSE (GET)."
	case http.StatusTooManyRequests: // 429
		return "Rate limited by remote server. Wait a moment and retry, or check your API plan quota."
	case http.StatusInternalServerError: // 500
		return "Remote server encountered an internal error. This is a server-side issue — contact the MCP provider."
	case http.StatusBadGateway: // 502
		return "Bad gateway response from upstream. The MCP server may be behind a misconfigured proxy or load balancer."
	case http.StatusServiceUnavailable: // 503
		return "Remote server is temporarily unavailable. It may be under maintenance or overloaded."
	case http.StatusGatewayTimeout: // 504
		return "Upstream server timed out. Check network connectivity or try again later."
	default:
		return fmt.Sprintf("Remote server returned unexpected HTTP %d %s.", statusCode, http.StatusText(statusCode))
	}
}

// ProbeResult contains the outcome of a successful MCP probe, including discovered tools
// and the negotiated transport mode for zero-overhead runtime dispatch.
type ProbeResult struct {
	Tools         []map[string]interface{} `json:"tools"`
	TransportMode string                   `json:"transport_mode"` // "sse" or "streamable_http"
}

// ProbeAndDiscoverMCPTools performs an active SSRF-safe MCP SSE handshake with targetURLStr to discover tools using DefaultSafeOptions.
func ProbeAndDiscoverMCPTools(targetURLStr string) ([]map[string]interface{}, error) {
	result, err := ProbeWithAutoNegotiation(context.Background(), nil, targetURLStr, "", nil, transport.DefaultSafeOptions())
	if err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// ProbeAndDiscoverMCPToolsWithOptions performs an active MCP SSE handshake with targetURLStr with configurable SSRF guardrail options.
func ProbeAndDiscoverMCPToolsWithOptions(targetURLStr string, opts transport.SafeTransportOptions) ([]map[string]interface{}, error) {
	result, err := ProbeWithAutoNegotiation(context.Background(), nil, targetURLStr, "", nil, opts)
	if err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// ProbeAndDiscoverMCPToolsWithContext performs an active MCP SSE handshake with targetURLStr using the provided context and client.
func ProbeAndDiscoverMCPToolsWithContext(ctx context.Context, client *http.Client, targetURLStr string, opts transport.SafeTransportOptions) ([]map[string]interface{}, error) {
	result, err := ProbeWithAutoNegotiation(ctx, client, targetURLStr, "", nil, opts)
	if err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// ProbeAndDiscoverMCPToolsWithContextAndAuth performs an active MCP SSE handshake with targetURLStr using the provided context, client, and optional auth token.
// If client is nil, a new safe HTTP client is constructed using opts and a 10-second timeout.
func ProbeAndDiscoverMCPToolsWithContextAndAuth(ctx context.Context, client *http.Client, targetURLStr, authToken string, opts transport.SafeTransportOptions) ([]map[string]interface{}, error) {
	result, err := ProbeWithAutoNegotiation(ctx, client, targetURLStr, authToken, nil, opts)
	if err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// ProbeAndDiscoverMCPToolsWithContextAuthAndHeaders performs an active MCP SSE handshake with targetURLStr using the provided context, client, optional auth token, and custom headers.
// If client is nil, a new safe HTTP client is constructed using opts and a 10-second timeout.
func ProbeAndDiscoverMCPToolsWithContextAuthAndHeaders(ctx context.Context, client *http.Client, targetURLStr, authToken string, customHeaders map[string]string, opts transport.SafeTransportOptions) ([]map[string]interface{}, error) {
	result, err := ProbeWithAutoNegotiation(ctx, client, targetURLStr, authToken, customHeaders, opts)
	if err != nil {
		return nil, err
	}
	return result.Tools, nil
}

// ProbeWithAutoNegotiation implements the dual-mode auto-negotiation engine.
// It tries legacy SSE first (GET + event:endpoint), and if that fails with a non-fatal
// error (405, non-SSE content, no endpoint event), falls back to Streamable HTTP
// (direct JSON-RPC POST). Returns a ProbeResult containing the discovered tools and
// the negotiated transport_mode ("sse" or "streamable_http").
func ProbeWithAutoNegotiation(ctx context.Context, client *http.Client, targetURLStr, authToken string, customHeaders map[string]string, opts transport.SafeTransportOptions) (*ProbeResult, error) {
	if targetURLStr == "" {
		return nil, fmt.Errorf("empty target URL")
	}

	// 0. Pre-validate destination URL against SSRF policy
	if err := transport.ValidateURL(targetURLStr, opts); err != nil {
		slog.WarnContext(ctx, "Target MCP URL rejected by SSRF guardrails", slog.String("target_url", targetURLStr), slog.String("error", err.Error()))
		return nil, fmt.Errorf("SSRF protection blocked probe target '%s': %w", targetURLStr, err)
	}

	slog.InfoContext(ctx, "SSRF-Safe probing target MCP server", slog.String("target_url", targetURLStr))
	if client == nil {
		client = transport.NewSafeHTTPClient(opts, 10*time.Second)
	}

	applyHeaders := func(r *http.Request) {
		if authToken != "" {
			if strings.HasPrefix(strings.ToLower(authToken), "bearer ") {
				r.Header.Set("Authorization", authToken)
			} else {
				r.Header.Set("Authorization", "Bearer "+authToken)
			}
		}
		for k, v := range customHeaders {
			k = strings.TrimSpace(k)
			if k != "" && !session.IsBlockedUpstreamHeader(k) {
				r.Header.Set(k, v)
			}
		}
	}

	// Step 1: Attempt legacy SSE probe (GET + Accept: text/event-stream)
	tools, sseErr := probeSSE(ctx, client, targetURLStr, applyHeaders, opts)
	if sseErr == nil {
		slog.InfoContext(ctx, "SSE probe successful", slog.String("target_url", targetURLStr), slog.Int("tool_count", len(tools)))
		return &ProbeResult{Tools: tools, TransportMode: "sse"}, nil
	}

	// Determine if SSE failure is fatal (auth/server errors) or negotiable (405, non-SSE content, no endpoint event)
	var upstreamErr *UpstreamHTTPError
	if errors.As(sseErr, &upstreamErr) {
		// 405 Method Not Allowed is a strong signal for Streamable HTTP — fall through
		if upstreamErr.StatusCode != http.StatusMethodNotAllowed {
			// For 401, 403, 404, 500, etc. — these are fatal, don't try Streamable HTTP
			return nil, sseErr
		}
		slog.InfoContext(ctx, "SSE probe returned 405, attempting Streamable HTTP fallback",
			slog.String("target_url", targetURLStr))
	} else {
		// Non-HTTP errors (no endpoint event, connection issues, non-SSE content) — try Streamable HTTP
		slog.InfoContext(ctx, "SSE probe did not succeed, attempting Streamable HTTP fallback",
			slog.String("target_url", targetURLStr),
			slog.String("sse_error", sseErr.Error()))
	}

	// Step 2: Attempt Streamable HTTP probe (direct JSON-RPC POST)
	tools, streamErr := probeStreamableHTTP(ctx, client, targetURLStr, applyHeaders)
	if streamErr == nil {
		slog.InfoContext(ctx, "Streamable HTTP probe successful", slog.String("target_url", targetURLStr), slog.Int("tool_count", len(tools)))
		return &ProbeResult{Tools: tools, TransportMode: "streamable_http"}, nil
	}

	// Both probes failed — return the Streamable HTTP error as primary (SSE was already non-negotiable)
	slog.WarnContext(ctx, "Both SSE and Streamable HTTP probes failed",
		slog.String("target_url", targetURLStr),
		slog.String("sse_error", sseErr.Error()),
		slog.String("streamable_error", streamErr.Error()),
	)
	return nil, streamErr
}

// probeSSE performs a legacy SSE probe: GET with Accept: text/event-stream,
// reads "event: endpoint", then sends initialize + tools/list via the discovered messages endpoint.
func probeSSE(ctx context.Context, client *http.Client, targetURLStr string, applyHeaders func(*http.Request), opts transport.SafeTransportOptions) ([]map[string]interface{}, error) {
	// 1. Connect to SSE endpoint (GET targetURLStr)
	req, err := http.NewRequestWithContext(ctx, "GET", targetURLStr, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		slog.WarnContext(ctx, "Failed to connect to SSE endpoint", slog.String("target_url", targetURLStr), slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to connect to SSE endpoint %s: %w", targetURLStr, err)
	}
	defer resp.Body.Close()

	// Immediately check HTTP status code — halt on non-200 with structured diagnostic error.
	if resp.StatusCode != http.StatusOK {
		slog.WarnContext(ctx, "Upstream MCP server returned non-200 HTTP status",
			slog.String("target_url", targetURLStr),
			slog.Int("status_code", resp.StatusCode),
			slog.String("status", resp.Status),
		)
		return nil, &UpstreamHTTPError{
			StatusCode:  resp.StatusCode,
			Category:    "UPSTREAM_HTTP_ERROR",
			Remediation: upstreamHTTPRemediation(resp.StatusCode),
		}
	}

	reader := bufio.NewReader(resp.Body)

	// Read until "event: endpoint"
	var messagesEndpointURL string
	var eventName string

	for i := 0; i < 50; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") && eventName == "endpoint" {
			dataVal := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			parsedTarget, pErr := url.Parse(targetURLStr)
			if pErr == nil {
				if strings.HasPrefix(dataVal, "http://") || strings.HasPrefix(dataVal, "https://") {
					messagesEndpointURL = dataVal
				} else {
					relURL, rErr := url.Parse(dataVal)
					if rErr == nil {
						messagesEndpointURL = parsedTarget.ResolveReference(relURL).String()
					} else {
						messagesEndpointURL = fmt.Sprintf("%s%s", targetURLStr, dataVal)
					}
				}
			}
			break
		}
	}

	if messagesEndpointURL == "" {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		slog.WarnContext(ctx, "No SSE endpoint event received", slog.String("target_url", targetURLStr))
		return nil, fmt.Errorf("did not receive SSE endpoint event from %s", targetURLStr)
	}

	// Validate dynamic messagesEndpointURL against SSRF policy before sending JSON-RPC payloads
	if err := transport.ValidateURL(messagesEndpointURL, opts); err != nil {
		slog.WarnContext(ctx, "Discovered messages endpoint rejected by SSRF guardrails", slog.String("endpoint_url", messagesEndpointURL), slog.String("error", err.Error()))
		return nil, fmt.Errorf("SSRF protection blocked discovered endpoint '%s': %w", messagesEndpointURL, err)
	}

	// 2. Send "initialize" POST
	initPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "FaradAiWireProber", "version": "1.0"},
		},
	}
	initBytes, _ := json.Marshal(initPayload)
	initReq, err := http.NewRequestWithContext(ctx, "POST", messagesEndpointURL, bytes.NewReader(initBytes))
	if err != nil {
		return nil, err
	}
	initReq.Header.Set("Content-Type", "application/json")
	applyHeaders(initReq)

	if initResp, err := client.Do(initReq); err == nil {
		initResp.Body.Close()
	} else if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// 3. Send "notifications/initialized" POST
	notifPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifBytes, _ := json.Marshal(notifPayload)
	notifReq, err := http.NewRequestWithContext(ctx, "POST", messagesEndpointURL, bytes.NewReader(notifBytes))
	if err != nil {
		return nil, err
	}
	notifReq.Header.Set("Content-Type", "application/json")
	applyHeaders(notifReq)

	if notifResp, err := client.Do(notifReq); err == nil {
		notifResp.Body.Close()
	} else if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// 4. Send "tools/list" POST
	toolsPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	toolsBytes, _ := json.Marshal(toolsPayload)
	toolsReq, err := http.NewRequestWithContext(ctx, "POST", messagesEndpointURL, bytes.NewReader(toolsBytes))
	if err != nil {
		return nil, err
	}
	toolsReq.Header.Set("Content-Type", "application/json")
	applyHeaders(toolsReq)

	toolsResp, err := client.Do(toolsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send tools/list to %s: %w", messagesEndpointURL, err)
	}
	defer toolsResp.Body.Close()

	bodyBytes, err := io.ReadAll(toolsResp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp struct {
		Result struct {
			Tools []map[string]interface{} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bodyBytes, &rpcResp); err == nil && len(rpcResp.Result.Tools) > 0 {
		return rpcResp.Result.Tools, nil
	}

	// Read from SSE stream if response was pushed on stream
	for i := 0; i < 50; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			dataVal := strings.TrimPrefix(line, "data:")
			var streamResp struct {
				Result struct {
					Tools []map[string]interface{} `json:"tools"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(dataVal), &streamResp); err == nil && len(streamResp.Result.Tools) > 0 {
				return streamResp.Result.Tools, nil
			}
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, fmt.Errorf("no tools returned from %s", targetURLStr)
}

// probeStreamableHTTP performs a Streamable HTTP probe: sends JSON-RPC initialize and
// tools/list directly via POST to the target URL (no SSE handshake).
func probeStreamableHTTP(ctx context.Context, client *http.Client, targetURLStr string, applyHeaders func(*http.Request)) ([]map[string]interface{}, error) {
	// 1. Send "initialize" via POST
	initPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "FaradAiWireProber", "version": "1.0"},
		},
	}
	initBytes, _ := json.Marshal(initPayload)
	initReq, err := http.NewRequestWithContext(ctx, "POST", targetURLStr, bytes.NewReader(initBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	initReq.Header.Set("Content-Type", "application/json")
	initReq.Header.Set("Accept", "application/json, text/event-stream")
	applyHeaders(initReq)

	initResp, err := client.Do(initReq)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Streamable HTTP endpoint %s: %w", targetURLStr, err)
	}
	defer initResp.Body.Close()

	if initResp.StatusCode != http.StatusOK {
		return nil, &UpstreamHTTPError{
			StatusCode:  initResp.StatusCode,
			Category:    "UPSTREAM_HTTP_ERROR",
			Remediation: upstreamHTTPRemediation(initResp.StatusCode),
		}
	}

	// Read and validate initialize response
	initBody, err := io.ReadAll(initResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read initialize response: %w", err)
	}

	// Handle SSE-wrapped response (Content-Type: text/event-stream)
	initBody = extractJSONFromSSEOrDirect(initBody)

	var initResult struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      interface{} `json:"id"`
		Result  struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(initBody, &initResult); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response from Streamable HTTP endpoint: %w", err)
	}
	if initResult.Error != nil {
		return nil, fmt.Errorf("Streamable HTTP initialize error: %s (code %d)", initResult.Error.Message, initResult.Error.Code)
	}

	slog.InfoContext(ctx, "Streamable HTTP initialize succeeded",
		slog.String("target_url", targetURLStr),
		slog.String("protocol_version", initResult.Result.ProtocolVersion))

	// 2. Send "notifications/initialized" (fire-and-forget)
	notifPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	notifBytes, _ := json.Marshal(notifPayload)
	notifReq, err := http.NewRequestWithContext(ctx, "POST", targetURLStr, bytes.NewReader(notifBytes))
	if err == nil {
		notifReq.Header.Set("Content-Type", "application/json")
		applyHeaders(notifReq)
		if notifResp, notifErr := client.Do(notifReq); notifErr == nil {
			notifResp.Body.Close()
		}
	}

	// 3. Send "tools/list" via POST
	toolsPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	toolsBytes, _ := json.Marshal(toolsPayload)
	toolsReq, err := http.NewRequestWithContext(ctx, "POST", targetURLStr, bytes.NewReader(toolsBytes))
	if err != nil {
		return nil, err
	}
	toolsReq.Header.Set("Content-Type", "application/json")
	toolsReq.Header.Set("Accept", "application/json, text/event-stream")
	applyHeaders(toolsReq)

	toolsResp, err := client.Do(toolsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send tools/list to %s: %w", targetURLStr, err)
	}
	defer toolsResp.Body.Close()

	toolsBody, err := io.ReadAll(toolsResp.Body)
	if err != nil {
		return nil, err
	}

	// Handle SSE-wrapped response
	toolsBody = extractJSONFromSSEOrDirect(toolsBody)

	var rpcResp struct {
		Result struct {
			Tools []map[string]interface{} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(toolsBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid tools/list JSON-RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("tools/list error: %s (code %d)", rpcResp.Error.Message, rpcResp.Error.Code)
	}

	return rpcResp.Result.Tools, nil
}

// extractJSONFromSSEOrDirect handles responses that may be either plain JSON or
// SSE-wrapped (text/event-stream with "data:" prefix lines). It extracts the first
// JSON payload from the data.
func extractJSONFromSSEOrDirect(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return trimmed
	}

	// Parse SSE-style response: look for "data:" lines containing JSON
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if len(data) > 0 && data[0] == '{' {
				return []byte(data)
			}
		}
	}
	return trimmed
}

// ProbeAndDiscoverMCPToolsStdio executes a local subprocess MCP server via stdin/stdout, performs the MCP initialization handshake, and calls tools/list.
func ProbeAndDiscoverMCPToolsStdio(ctx context.Context, command string, args []string, env []string) ([]map[string]interface{}, error) {
	trimmedCmd := strings.TrimSpace(command)
	if trimmedCmd == "" {
		return nil, errors.New("command cannot be empty for stdio probe")
	}

	cmd := exec.CommandContext(ctx, trimmedCmd, args...)

	// Build environment with variable expansion
	if len(env) > 0 {
		resolvedEnv := os.Environ()
		for _, e := range env {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				val := parts[1]
				if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
					varName := strings.TrimSuffix(strings.TrimPrefix(val, "${"), "}")
					val = os.Getenv(varName)
				}
				resolvedEnv = append(resolvedEnv, parts[0]+"="+val)
			} else {
				resolvedEnv = append(resolvedEnv, e)
			}
		}
		cmd.Env = resolvedEnv
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinPipe.Close()
		return nil, fmt.Errorf("failed to open stdout pipe: %w", err)
	}

	var stderrBuf safeBuffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		return nil, fmt.Errorf("failed to start stdio subprocess '%s': %w", trimmedCmd, err)
	}

	defer func() {
		_ = stdinPipe.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdoutPipe)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	// 1. Send "initialize" request (id: 1)
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"FaradAiWireProber","version":"1.0"}}}` + "\n"
	if _, err := io.WriteString(stdinPipe, initReq); err != nil {
		return nil, fmt.Errorf("failed to write initialize request: %w", err)
	}

	// Read until response with id: 1
	var initReceived bool
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg struct {
			ID    interface{} `json:"id"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &msg); err == nil && msg.ID != nil {
			if msg.Error != nil {
				return nil, fmt.Errorf("initialize error from stdio subprocess: %s", msg.Error.Message)
			}
			initReceived = true
			break
		}
	}

	if !initReceived {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("stdio process did not respond to initialize: %s", stderrBuf.String())
	}

	// 2. Send "notifications/initialized"
	notif := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	if _, err := io.WriteString(stdinPipe, notif); err != nil {
		return nil, fmt.Errorf("failed to write initialized notification: %w", err)
	}

	// 3. Send "tools/list" request (id: 2)
	toolsReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	if _, err := io.WriteString(stdinPipe, toolsReq); err != nil {
		return nil, fmt.Errorf("failed to write tools/list request: %w", err)
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp struct {
			ID     interface{} `json:"id"`
			Result struct {
				Tools []map[string]interface{} `json:"tools"`
			} `json:"result"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err == nil {
			if resp.Error != nil {
				return nil, fmt.Errorf("tools/list error: %s (code %d)", resp.Error.Message, resp.Error.Code)
			}
			if resp.ID != nil {
				return resp.Result.Tools, nil
			}
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stdio output: %w", err)
	}

	return nil, fmt.Errorf("no tools returned from stdio subprocess: %s", stderrBuf.String())
}
