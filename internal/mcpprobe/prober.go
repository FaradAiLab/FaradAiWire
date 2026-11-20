// Package mcpprobe implements SSRF-safe Model Context Protocol (MCP) probing
// and tool discovery across legacy SSE, Streamable HTTP, and sandboxed stdio transports.
package mcpprobe

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
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

const (
	maxSafeBufferBytes = 64 * 1024 // retain at most the most recent 64 KiB of subprocess stderr
	maxSafeLineBytes   = 4 * 1024  // cap per-line progress accumulator before newline/\r
	maxProbeBodyBytes  = 10 << 20  // 10 MiB upstream JSON-RPC response cap
)

// safeBuffer provides a thread-safe bounded bytes.Buffer wrapper for concurrent subprocess stdio
// with an optional line-by-line progress callback (triggered on \n or \r).
type safeBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	lineAcc bytes.Buffer
	onLine  func(string)
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	var completed []string

	s.mu.Lock()
	n, err = s.buf.Write(p)
	// Keep retention amortized O(1) by compacting back down to the tail limit when doubled.
	if s.buf.Len() > maxSafeBufferBytes*2 {
		tail := append([]byte(nil), s.buf.Bytes()[s.buf.Len()-maxSafeBufferBytes:]...)
		s.buf.Reset()
		s.buf.Write(tail)
	}
	if s.onLine != nil {
		for _, b := range p {
			if b == '\n' || b == '\r' {
				if line := strings.TrimSpace(s.lineAcc.String()); line != "" {
					completed = append(completed, line)
				}
				s.lineAcc.Reset()
			} else if s.lineAcc.Len() < maxSafeLineBytes {
				s.lineAcc.WriteByte(b)
			}
		}
	}
	cb := s.onLine
	s.mu.Unlock()

	if cb != nil {
		for _, line := range completed {
			cb(line)
		}
	}
	return n, err
}

func (s *safeBuffer) FlushPending() {
	s.mu.Lock()
	var line string
	if s.onLine != nil {
		line = strings.TrimSpace(s.lineAcc.String())
		s.lineAcc.Reset()
	}
	cb := s.onLine
	s.mu.Unlock()

	if cb != nil && line != "" {
		cb(line)
	}
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf.Len() > maxSafeBufferBytes {
		return string(s.buf.Bytes()[s.buf.Len()-maxSafeBufferBytes:])
	}
	return s.buf.String()
}

// UpstreamHTTPError represents a structured diagnostic error returned when an upstream MCP server
// responds with a non-200 HTTP status code during probing. It carries the exact status code,
// error category, and a human-readable remediation message so callers can render actionable guidance.
type UpstreamHTTPError struct {
	StatusCode  int    `json:"status_code"`
	Category    string `json:"category"`
	Remediation string `json:"remediation"`
}

// Error implements the error interface for UpstreamHTTPError.
func (e *UpstreamHTTPError) Error() string {
	return fmt.Sprintf("HTTP %d %s from upstream: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Remediation)
}

func upstreamHTTPRemediation(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized:
		return "Remote server rejected credentials. Verify your Authentication Token or add the required API key header."
	case http.StatusForbidden:
		return "Access denied by remote server. Check that your credentials have sufficient permissions or the IP allowlist includes this Gateway."
	case http.StatusNotFound:
		return "Endpoint not found. Verify the URL path is correct and the MCP server is deployed at this address."
	case http.StatusMethodNotAllowed:
		return "Server does not accept this HTTP method. The endpoint may use Streamable HTTP (POST) instead of legacy SSE (GET)."
	case http.StatusTooManyRequests:
		return "Rate limited by remote server. Wait a moment and retry, or check your API plan quota."
	case http.StatusInternalServerError:
		return "Remote server encountered an internal error. This is a server-side issue — contact the MCP provider."
	case http.StatusBadGateway:
		return "Bad gateway response from upstream. The MCP server may be behind a misconfigured proxy or load balancer."
	case http.StatusServiceUnavailable:
		return "Remote server is temporarily unavailable. It may be under maintenance or overloaded."
	case http.StatusGatewayTimeout:
		return "Upstream server timed out. Check network connectivity or try again later."
	default:
		return fmt.Sprintf("Remote server returned unexpected HTTP %d %s.", statusCode, http.StatusText(statusCode))
	}
}

// ProbeRequest configures an SSRF-safe HTTP/SSE MCP endpoint probe.
type ProbeRequest struct {
	Client        *http.Client
	TargetURL     string
	AuthToken     string
	CustomHeaders map[string]string
	SSRFOptions   transport.SafeTransportOptions
}

// StdioProbeRequest configures a sandboxed local MCP subprocess probe.
type StdioProbeRequest struct {
	Command    string
	Args       []string
	Env        []string
	OnProgress func(string)
}

// ProbeResult contains the outcome of a successful MCP probe, including discovered tools
// and the negotiated transport mode for runtime dispatch.
type ProbeResult struct {
	Tools         []map[string]interface{} `json:"tools"`
	TransportMode string                   `json:"transport_mode"` // "sse" or "streamable_http"
}

// IsPackageRunnerCommand reports whether command invokes an ephemeral package launcher
// (such as uvx, npx, or docker) that may need an extended cold-start timeout.
func IsPackageRunnerCommand(command string) bool {
	base := strings.TrimSpace(command)
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.ToLower(strings.TrimSuffix(base, ".exe"))
	switch base {
	case "uvx", "uv", "npx", "bunx", "pnpm", "yarn", "pipx", "docker", "podman":
		return true
	default:
		return false
	}
}

// ProbeHTTP executes an SSRF-validated MCP endpoint probe with automatic transport negotiation.
// It tries legacy SSE first (GET + event:endpoint), and falls back to Streamable HTTP
// (direct JSON-RPC POST) on non-fatal negotiation failures such as HTTP 405 or missing SSE streams.
func ProbeHTTP(ctx context.Context, req ProbeRequest) (*ProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.TargetURL == "" {
		return nil, errors.New("empty target URL")
	}

	if err := transport.ValidateURL(req.TargetURL, req.SSRFOptions); err != nil {
		slog.WarnContext(ctx, "Target MCP URL rejected by SSRF guardrails", slog.String("target_url", req.TargetURL), slog.String("error", err.Error()))
		return nil, fmt.Errorf("SSRF protection blocked probe target '%s': %w", req.TargetURL, err)
	}

	slog.InfoContext(ctx, "SSRF-Safe probing target MCP server", slog.String("target_url", req.TargetURL))
	client := req.Client
	if client == nil {
		timeout := 10 * time.Second
		if dl, ok := ctx.Deadline(); ok {
			if rem := time.Until(dl); rem > 0 {
				timeout = rem
			}
		}
		client = transport.NewSafeHTTPClient(req.SSRFOptions, timeout)
	}

	applyHeaders := buildHeaderApplier(req.AuthToken, req.CustomHeaders)

	tools, sseErr := probeSSE(ctx, client, req.TargetURL, applyHeaders, req.SSRFOptions)
	if sseErr == nil {
		slog.InfoContext(ctx, "SSE probe successful", slog.String("target_url", req.TargetURL), slog.Int("tool_count", len(tools)))
		return &ProbeResult{Tools: tools, TransportMode: "sse"}, nil
	}

	var upstreamErr *UpstreamHTTPError
	if errors.As(sseErr, &upstreamErr) {
		if upstreamErr.StatusCode != http.StatusMethodNotAllowed {
			return nil, sseErr
		}
		slog.InfoContext(ctx, "SSE probe returned 405, attempting Streamable HTTP fallback",
			slog.String("target_url", req.TargetURL))
	} else {
		slog.InfoContext(ctx, "SSE probe did not succeed, attempting Streamable HTTP fallback",
			slog.String("target_url", req.TargetURL),
			slog.String("sse_error", sseErr.Error()))
	}

	tools, streamErr := probeStreamableHTTP(ctx, client, req.TargetURL, applyHeaders)
	if streamErr == nil {
		slog.InfoContext(ctx, "Streamable HTTP probe successful", slog.String("target_url", req.TargetURL), slog.Int("tool_count", len(tools)))
		return &ProbeResult{Tools: tools, TransportMode: "streamable_http"}, nil
	}

	slog.WarnContext(ctx, "Both SSE and Streamable HTTP probes failed",
		slog.String("target_url", req.TargetURL),
		slog.String("sse_error", sseErr.Error()),
		slog.String("streamable_error", streamErr.Error()),
	)
	return nil, streamErr
}

func buildHeaderApplier(authToken string, customHeaders map[string]string) func(*http.Request) {
	return func(r *http.Request) {
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
}

func probeSSE(ctx context.Context, client *http.Client, targetURLStr string, applyHeaders func(*http.Request), opts transport.SafeTransportOptions) ([]map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURLStr, nil)
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
	messagesEndpointURL, err := readSSEEndpointURL(ctx, reader, targetURLStr)
	if err != nil {
		return nil, err
	}

	if err := validateSameOriginEndpoint(ctx, targetURLStr, messagesEndpointURL, opts); err != nil {
		return nil, err
	}

	if err := sendInitializePOST(ctx, client, messagesEndpointURL, applyHeaders); err != nil {
		return nil, err
	}
	if err := sendInitializedNotification(ctx, client, messagesEndpointURL, applyHeaders); err != nil {
		return nil, err
	}

	return sendToolsListSSE(ctx, client, reader, targetURLStr, messagesEndpointURL, applyHeaders)
}

func readSSEEndpointURL(ctx context.Context, reader *bufio.Reader, targetURLStr string) (string, error) {
	var messagesEndpointURL string
	var eventName string

	for i := 0; i < 50; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
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
				} else if relURL, rErr := url.Parse(dataVal); rErr == nil {
					messagesEndpointURL = parsedTarget.ResolveReference(relURL).String()
				} else {
					messagesEndpointURL = fmt.Sprintf("%s%s", targetURLStr, dataVal)
				}
			}
			break
		}
	}

	if messagesEndpointURL == "" {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		slog.WarnContext(ctx, "No SSE endpoint event received", slog.String("target_url", targetURLStr))
		return "", fmt.Errorf("did not receive SSE endpoint event from %s", targetURLStr)
	}
	return messagesEndpointURL, nil
}

func validateSameOriginEndpoint(ctx context.Context, targetURLStr, messagesEndpointURL string, opts transport.SafeTransportOptions) error {
	epURL, epErr := url.Parse(messagesEndpointURL)
	parsedBase, baseErr := url.Parse(targetURLStr)
	if epErr != nil || baseErr != nil || epURL.User != nil ||
		!strings.EqualFold(epURL.Scheme, parsedBase.Scheme) || !strings.EqualFold(epURL.Host, parsedBase.Host) {
		slog.WarnContext(ctx, "Discovered SSE endpoint rejected due to cross-origin or invalid URL", slog.String("target_url", targetURLStr), slog.String("endpoint_url", messagesEndpointURL))
		return fmt.Errorf("SSE endpoint event origin mismatch for %s", targetURLStr)
	}
	if err := transport.ValidateURL(messagesEndpointURL, opts); err != nil {
		slog.WarnContext(ctx, "Discovered messages endpoint rejected by SSRF guardrails", slog.String("endpoint_url", messagesEndpointURL), slog.String("error", err.Error()))
		return fmt.Errorf("SSRF protection blocked discovered endpoint '%s': %w", messagesEndpointURL, err)
	}
	return nil
}

func newInitializeBytes() ([]byte, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "FaradAiWireProber", "version": "1.0"},
		},
	}
	return json.Marshal(payload)
}

func sendInitializePOST(ctx context.Context, client *http.Client, endpointURL string, applyHeaders func(*http.Request)) error {
	initBytes, err := newInitializeBytes()
	if err != nil {
		return fmt.Errorf("marshal initialize payload: %w", err)
	}
	initReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(initBytes))
	if err != nil {
		return err
	}
	initReq.Header.Set("Content-Type", "application/json")
	applyHeaders(initReq)

	if initResp, err := client.Do(initReq); err == nil {
		_ = initResp.Body.Close()
	} else if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return nil
}

func sendInitializedNotification(ctx context.Context, client *http.Client, endpointURL string, applyHeaders func(*http.Request)) error {
	notifBytes, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	if err != nil {
		return fmt.Errorf("marshal initialized notification: %w", err)
	}
	notifReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(notifBytes))
	if err != nil {
		return err
	}
	notifReq.Header.Set("Content-Type", "application/json")
	applyHeaders(notifReq)

	if notifResp, err := client.Do(notifReq); err == nil {
		_ = notifResp.Body.Close()
	} else if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return nil
}

func sendToolsListSSE(ctx context.Context, client *http.Client, reader *bufio.Reader, targetURLStr, messagesEndpointURL string, applyHeaders func(*http.Request)) ([]map[string]interface{}, error) {
	toolsBytes, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tools/list request: %w", err)
	}
	toolsReq, err := http.NewRequestWithContext(ctx, http.MethodPost, messagesEndpointURL, bytes.NewReader(toolsBytes))
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

	bodyBytes, err := io.ReadAll(io.LimitReader(toolsResp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read tools/list response: %w", err)
	}

	var rpcResp struct {
		Result struct {
			Tools []map[string]interface{} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bodyBytes, &rpcResp); err == nil && len(rpcResp.Result.Tools) > 0 {
		return rpcResp.Result.Tools, nil
	}

	for i := 0; i < 50; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
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

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no tools returned from %s", targetURLStr)
}

func probeStreamableHTTP(ctx context.Context, client *http.Client, targetURLStr string, applyHeaders func(*http.Request)) ([]map[string]interface{}, error) {
	initBytes, err := newInitializeBytes()
	if err != nil {
		return nil, fmt.Errorf("marshal initialize payload: %w", err)
	}
	initReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURLStr, bytes.NewReader(initBytes))
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

	initBody, err := io.ReadAll(io.LimitReader(initResp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read initialize response: %w", err)
	}

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

	// Fire-and-forget notifications/initialized
	if notifBytes, mErr := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}); mErr == nil {
		if notifReq, rErr := http.NewRequestWithContext(ctx, http.MethodPost, targetURLStr, bytes.NewReader(notifBytes)); rErr == nil {
			notifReq.Header.Set("Content-Type", "application/json")
			applyHeaders(notifReq)
			if notifResp, notifErr := client.Do(notifReq); notifErr == nil {
				_ = notifResp.Body.Close()
			}
		}
	}

	toolsBytes, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tools/list payload: %w", err)
	}
	toolsReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURLStr, bytes.NewReader(toolsBytes))
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

	toolsBody, err := io.ReadAll(io.LimitReader(toolsResp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read tools/list response: %w", err)
	}

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

func extractJSONFromSSEOrDirect(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return trimmed
	}

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

func formatStdioTimeoutError(command string, ctxErr error, stderr string) error {
	trimmedErr := strings.TrimSpace(stderr)
	if trimmedErr != "" {
		const maxStderrLen = 400
		if len(trimmedErr) > maxStderrLen {
			trimmedErr = trimmedErr[len(trimmedErr)-maxStderrLen:]
		}
		return fmt.Errorf("stdio subprocess '%s' timed out before responding (%w); stderr: %s", command, ctxErr, trimmedErr)
	}
	return fmt.Errorf("stdio subprocess '%s' timed out before responding (%w) — cold-start package downloads (uvx/npx) may need more time; increase timeouts.probe_timeout_sec in Operational Settings", command, ctxErr)
}

// ProbeStdio executes a sanitized local MCP subprocess via stdin/stdout, performs the MCP
// initialization handshake, streams optional stderr progress lines, and returns discovered tools.
func ProbeStdio(ctx context.Context, req StdioProbeRequest) ([]map[string]interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	trimmedCmd := strings.TrimSpace(req.Command)
	if trimmedCmd == "" {
		return nil, errors.New("command cannot be empty for stdio probe")
	}

	cmd := exec.CommandContext(ctx, trimmedCmd, req.Args...)
	// Always construct a minimal sanitized environment even when Env is empty so host secrets
	// (API_KEY, ADMIN_API_KEY, cloud tokens) never leak to probed stdio processes.
	cmd.Env = session.BuildSafeSubprocessEnv(req.Env, true)
	procGuard := configureProbeProcess(cmd)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinPipe.Close()
		return nil, fmt.Errorf("failed to open stdout pipe: %w", err)
	}

	stderrBuf := safeBuffer{onLine: req.OnProgress}
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		_ = stdoutPipe.Close()
		return nil, fmt.Errorf("failed to start stdio subprocess '%s': %w", trimmedCmd, err)
	}
	procGuard.afterStart()

	stopAfter := context.AfterFunc(ctx, procGuard.killTree)
	defer func() {
		stopAfter()
		_ = stdinPipe.Close()
		procGuard.killTree()
		procGuard.markReaped()
		_ = cmd.Wait()
		stderrBuf.FlushPending()
	}()

	scanner := bufio.NewScanner(stdoutPipe)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxProbeBodyBytes)

	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"FaradAiWireProber","version":"1.0"}}}` + "\n"
	if _, err := io.WriteString(stdinPipe, initReq); err != nil {
		return nil, fmt.Errorf("failed to write initialize request: %w", err)
	}

	if err := awaitStdioInitialize(ctx, scanner, trimmedCmd, &stderrBuf); err != nil {
		return nil, err
	}

	notif := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	if _, err := io.WriteString(stdinPipe, notif); err != nil {
		return nil, fmt.Errorf("failed to write initialized notification: %w", err)
	}

	toolsReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	if _, err := io.WriteString(stdinPipe, toolsReq); err != nil {
		return nil, fmt.Errorf("failed to write tools/list request: %w", err)
	}

	return awaitStdioToolsList(ctx, scanner, trimmedCmd, &stderrBuf)
}

func awaitStdioInitialize(ctx context.Context, scanner *bufio.Scanner, trimmedCmd string, stderrBuf *safeBuffer) error {
	for scanner.Scan() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return formatStdioTimeoutError(trimmedCmd, ctxErr, stderrBuf.String())
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
				return fmt.Errorf("initialize error from stdio subprocess: %s", msg.Error.Message)
			}
			return nil
		}
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return formatStdioTimeoutError(trimmedCmd, ctxErr, stderrBuf.String())
	}
	return fmt.Errorf("stdio process did not respond to initialize: %s", stderrBuf.String())
}

func awaitStdioToolsList(ctx context.Context, scanner *bufio.Scanner, trimmedCmd string, stderrBuf *safeBuffer) ([]map[string]interface{}, error) {
	for scanner.Scan() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, formatStdioTimeoutError(trimmedCmd, ctxErr, stderrBuf.String())
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

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, formatStdioTimeoutError(trimmedCmd, ctxErr, stderrBuf.String())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stdio output: %w", err)
	}

	return nil, fmt.Errorf("no tools returned from stdio subprocess: %s", stderrBuf.String())
}
