package session

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// Dialer provides upstream MCP SSE connection establishment.
type Dialer interface {
	Dial(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession
}

// HTTPDialer implements Dialer using an HTTP client.
type HTTPDialer struct {
	client      *http.Client
	dialTimeout time.Duration
}

// NewHTTPDialer creates a new HTTPDialer.
func NewHTTPDialer(client *http.Client, dialTimeout time.Duration) *HTTPDialer {
	if client == nil {
		client = &http.Client{Timeout: 0}
	}
	if dialTimeout <= 0 {
		dialTimeout = 500 * time.Millisecond
	}
	return &HTTPDialer{
		client:      client,
		dialTimeout: dialTimeout,
	}
}

// Dial connects to the upstream MCP SSE endpoint and spawns a stream consumer.
func (d *HTTPDialer) Dial(parentCtx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
	upSess := &UpstreamSession{
		ProtocolID:   proto.ID,
		ProtocolName: proto.Name,
		URLOrCommand: proto.URLOrCommand,
		Type:         proto.Type,
		TargetScope:  proto.TargetScope,
		AuthToken:    proto.AuthToken,
		Headers:      proto.Headers,
		Status:       "CONNECTING",
		LastPing:     time.Now(),
	}

	backendURL, err := url.Parse(proto.URLOrCommand)
	if err != nil {
		upSess.SetStatus("DEGRADED")
		slog.Error("Invalid upstream URL",
			slog.String("protocol", proto.Name),
			slog.String("url", proto.URLOrCommand),
			slog.String("error", err.Error()),
		)
		return upSess
	}

	streamCtx, streamCancel := context.WithCancel(parentCtx)
	upSess.Cancel = streamCancel

	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, backendURL.String(), nil)
	if err != nil {
		streamCancel()
		upSess.SetStatus("DEGRADED")
		slog.Error("Failed to build upstream request",
			slog.String("protocol", proto.Name),
			slog.String("error", err.Error()),
		)
		return upSess
	}

	sanitizedHeaders := SanitizeUpstreamHeadersWithCustom(headers, proto.AuthToken, proto.Headers)
	for k, vv := range sanitizedHeaders {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	type dialResult struct {
		resp *http.Response
		err  error
	}
	dialResCh := make(chan dialResult, 1)

	go func() {
		resp, reqErr := d.client.Do(req)
		dialResCh <- dialResult{resp: resp, err: reqErr}
	}()

	var resp *http.Response
	select {
	case <-time.After(d.dialTimeout):
		streamCancel()
		upSess.SetStatus("DEGRADED")
		slog.Warn("Upstream dial timed out",
			slog.String("protocol", proto.Name),
			slog.String("url", proto.URLOrCommand),
			slog.Duration("timeout", d.dialTimeout),
		)
		return upSess
	case <-streamCtx.Done():
		streamCancel()
		upSess.SetStatus("CLOSED")
		return upSess
	case res := <-dialResCh:
		if res.err != nil {
			streamCancel()
			upSess.SetStatus("DEGRADED")
			slog.Warn("Failed to dial upstream protocol",
				slog.String("protocol", proto.Name),
				slog.String("url", proto.URLOrCommand),
				slog.String("error", res.err.Error()),
			)
			return upSess
		}
		resp = res.resp
	}

	upSess.SetLastDialStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		streamCancel()
		upSess.SetStatus("DEGRADED")
		slog.Warn("Upstream protocol returned non-200 status",
			slog.String("protocol", proto.Name),
			slog.Int("status", resp.StatusCode),
		)
		return upSess
	}

	upSess.SetStatus("READY")

	endpointDone := make(chan struct{})
	var endpointOnce sync.Once

	// Close resp.Body promptly when context is canceled to unblock reader
	go func() {
		<-streamCtx.Done()
		_ = resp.Body.Close()
	}()

	// Read SSE stream in background goroutine
	go func() {
		defer resp.Body.Close()
		defer streamCancel()
		defer upSess.SetStatus("CLOSED")
		defer endpointOnce.Do(func() { close(endpointDone) })

		reader := bufio.NewReader(resp.Body)
		var eventName string
		var eventDataBuilder strings.Builder

		for {
			select {
			case <-streamCtx.Done():
				return
			default:
			}

			line, rErr := reader.ReadString('\n')
			if rErr != nil {
				if rErr != io.EOF && streamCtx.Err() == nil {
					slog.Debug("Stream closed for protocol",
						slog.String("protocol", proto.Name),
						slog.String("error", rErr.Error()),
					)
				}
				return
			}

			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")

			if line == "" {
				// End of event packet
				if eventName != "" || eventDataBuilder.Len() > 0 {
					data := eventDataBuilder.String()
					if eventName == "endpoint" {
						// Intercept backend endpoint event to record upstream session details
						upSess.SetStatus("READY")
						msgPath := strings.TrimSpace(data)
						upSess.SetBackendMessageURL(msgPath)

						if u, parseErr := url.Parse(msgPath); parseErr == nil {
							sid := u.Query().Get("sessionId")
							if sid == "" {
								sid = u.Query().Get("session_id")
							}
							if sid != "" {
								upSess.SetBackendSessionID(sid)
							}
						}
						endpointOnce.Do(func() { close(endpointDone) })
					} else {
						// Forward downstream
						select {
						case eventCh <- SSEEvent{
							Event:        eventName,
							Data:         data,
							ProtocolName: proto.Name,
						}:
						case <-streamCtx.Done():
							return
						}
					}
				}
				eventName = ""
				eventDataBuilder.Reset()
				continue
			}

			if strings.HasPrefix(line, ":") {
				// SSE comment / heartbeat
				upSess.mu.Lock()
				upSess.LastPing = time.Now()
				upSess.mu.Unlock()
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
			}
		}
	}()

	select {
	case <-endpointDone:
	case <-time.After(d.dialTimeout):
	}

	return upSess
}

// BuildTargetMessageURL constructs the fully-qualified backend POST URL for a tool call.
func BuildTargetMessageURL(protoURL, backendMsgPath string) (string, error) {
	if backendMsgPath == "" {
		backendMsgPath = "/message"
	}

	base, err := url.Parse(protoURL)
	if err != nil {
		return "", fmt.Errorf("invalid proto base URL '%s': %w", protoURL, err)
	}

	if strings.HasPrefix(backendMsgPath, "http://") || strings.HasPrefix(backendMsgPath, "https://") {
		return backendMsgPath, nil
	}

	rel, err := url.Parse(backendMsgPath)
	if err != nil {
		return "", fmt.Errorf("invalid backend msg path '%s': %w", backendMsgPath, err)
	}

	return base.ResolveReference(rel).String(), nil
}

// StdioDialer establishes and manages local stdio subprocess MCP backends.
type StdioDialer struct{}

// NewStdioDialer creates a new StdioDialer.
func NewStdioDialer() *StdioDialer {
	return &StdioDialer{}
}

// Dial spawns the configured local command and attaches stdin/stdout pipes for JSON-RPC communication.
func (d *StdioDialer) Dial(parentCtx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
	upSess := &UpstreamSession{
		ProtocolID:   proto.ID,
		ProtocolName: proto.Name,
		URLOrCommand: proto.URLOrCommand,
		Type:         "stdio",
		TargetScope:  proto.TargetScope,
		AuthToken:    proto.AuthToken,
		Status:       "CONNECTING",
		LastPing:     time.Now(),
		pendingCalls: make(map[string]chan *mcp.Response),
		procExitCh:   make(chan struct{}),
	}

	command := proto.GetCommand()
	if strings.TrimSpace(command) == "" {
		upSess.SetStatus("DEGRADED")
		upSess.procExitOnce.Do(func() { close(upSess.procExitCh) })
		slog.Error("Empty command for stdio protocol", slog.String("protocol", proto.Name))
		return upSess
	}

	args := proto.Args
	if len(args) == 0 {
		fields := strings.Fields(command)
		if len(fields) > 1 {
			command = fields[0]
			args = fields[1:]
		}
	}

	procCtx, procCancel := context.WithCancel(parentCtx)
	upSess.Cancel = procCancel

	cmd := exec.CommandContext(procCtx, command, args...)
	setProcessGroup(cmd)
	setCommandCancel(cmd)
	cmd.Env = buildSafeSubprocessEnv(proto.Env)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		procCancel()
		upSess.SetStatus("DEGRADED")
		upSess.procExitOnce.Do(func() { close(upSess.procExitCh) })
		slog.Error("Failed to create stdin pipe for stdio protocol",
			slog.String("protocol", proto.Name),
			slog.String("error", err.Error()),
		)
		return upSess
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		procCancel()
		_ = stdinPipe.Close()
		upSess.SetStatus("DEGRADED")
		upSess.procExitOnce.Do(func() { close(upSess.procExitCh) })
		slog.Error("Failed to create stdout pipe for stdio protocol",
			slog.String("protocol", proto.Name),
			slog.String("error", err.Error()),
		)
		return upSess
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		procCancel()
		_ = stdinPipe.Close()
		upSess.SetStatus("DEGRADED")
		upSess.procExitOnce.Do(func() { close(upSess.procExitCh) })
		slog.Error("Failed to start stdio subprocess",
			slog.String("protocol", proto.Name),
			slog.String("command", command),
			slog.String("error", err.Error()),
		)
		return upSess
	}

	upSess.cmd = cmd
	upSess.stdin = stdinPipe
	upSess.SetStatus("READY")

	slog.Info("Started local stdio MCP subprocess",
		slog.String("protocol", proto.Name),
		slog.String("command", command),
		slog.Int("pid", cmd.Process.Pid),
	)

	// Background reader for stdout JSON-RPC messages
	go func() {
		defer func() {
			_ = stdinPipe.Close()
			_ = cmd.Wait()
			if upSess.procExitCh != nil {
				upSess.procExitOnce.Do(func() {
					close(upSess.procExitCh)
				})
			}
			// Drain and close all pending calls to wake up any blocked callers immediately
			upSess.pendingCallsMu.Lock()
			for reqID, ch := range upSess.pendingCalls {
				if ch != nil {
					close(ch)
				}
				delete(upSess.pendingCalls, reqID)
			}
			upSess.pendingCallsMu.Unlock()

			upSess.SetStatus("CLOSED")
			procCancel()
		}()

		scanner := bufio.NewScanner(stdoutPipe)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		for scanner.Scan() {
			lineBytes := bytes.TrimSpace(scanner.Bytes())
			if len(lineBytes) == 0 {
				continue
			}

			upSess.mu.Lock()
			upSess.LastPing = time.Now()
			upSess.mu.Unlock()

			req, resp, isRequest, err := mcp.ParseMessage(lineBytes)
			if err != nil {
				slog.Debug("Failed to parse line from stdio subprocess",
					slog.String("protocol", proto.Name),
					slog.String("line", string(lineBytes)),
					slog.String("error", err.Error()),
				)
				continue
			}

			if !isRequest && resp != nil {
				reqIDStr := fmt.Sprintf("%v", resp.ID)
				upSess.pendingCallsMu.Lock()
				ch, ok := upSess.pendingCalls[reqIDStr]
				upSess.pendingCallsMu.Unlock()

				if ok && ch != nil {
					select {
					case ch <- resp:
					default:
					}
				}
			} else if isRequest && req != nil && eventCh != nil {
				// Server notification from stdio subprocess
				select {
				case eventCh <- SSEEvent{
					Event:        "message",
					Data:         string(lineBytes),
					ProtocolName: proto.Name,
				}:
				case <-procCtx.Done():
					return
				}
			}
		}

		if err := scanner.Err(); err != nil && procCtx.Err() == nil {
			slog.Warn("Stdio scanner error",
				slog.String("protocol", proto.Name),
				slog.String("error", err.Error()),
			)
		}
	}()

	return upSess
}

// StreamableHTTPDialer establishes lightweight Streamable HTTP sessions without long-lived SSE connections.
// It validates the upstream URL, applies credential injection, and marks the session READY immediately.
type StreamableHTTPDialer struct{}

// NewStreamableHTTPDialer creates a new StreamableHTTPDialer.
func NewStreamableHTTPDialer() *StreamableHTTPDialer {
	return &StreamableHTTPDialer{}
}

// Dial creates a lightweight UpstreamSession for Streamable HTTP protocols.
// No long-lived SSE connection is established — tool calls are dispatched as direct JSON-RPC POSTs.
func (d *StreamableHTTPDialer) Dial(parentCtx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
	upSess := &UpstreamSession{
		ProtocolID:   proto.ID,
		ProtocolName: proto.Name,
		URLOrCommand: proto.URLOrCommand,
		Type:         proto.Type,
		TargetScope:  proto.TargetScope,
		AuthToken:    proto.AuthToken,
		Headers:      proto.Headers,
		Status:       "CONNECTING",
		LastPing:     time.Now(),
	}

	parsed, err := url.Parse(proto.URLOrCommand)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		upSess.SetStatus("DEGRADED")
		slog.Error("Invalid upstream URL for Streamable HTTP",
			slog.String("protocol", proto.Name),
			slog.String("url", proto.URLOrCommand),
			slog.Any("error", err),
		)
		return upSess
	}

	sessCtx, sessCancel := context.WithCancel(parentCtx)
	upSess.Cancel = sessCancel

	// No long-lived connection — immediately mark READY.
	// Tool calls are dispatched as direct JSON-RPC POSTs via CallToolHTTP.
	upSess.SetStatus("READY")
	slog.Info("Streamable HTTP session established (stateless)",
		slog.String("protocol", proto.Name),
		slog.String("url", proto.URLOrCommand),
	)

	// Background context watcher to mark session closed when parent context is done
	go func() {
		<-sessCtx.Done()
		upSess.SetStatus("CLOSED")
	}()

	return upSess
}

// CompositeDialer multiplexes between HTTPDialer, StdioDialer, and StreamableHTTPDialer based on protocol type.
type CompositeDialer struct {
	httpDialer           Dialer
	stdioDialer          Dialer
	streamableHTTPDialer Dialer
}

// NewCompositeDialer creates a new CompositeDialer.
func NewCompositeDialer(httpDialer Dialer, stdioDialer Dialer) *CompositeDialer {
	if httpDialer == nil {
		httpDialer = NewHTTPDialer(nil, 500*time.Millisecond)
	}
	if stdioDialer == nil {
		stdioDialer = NewStdioDialer()
	}
	return &CompositeDialer{
		httpDialer:           httpDialer,
		stdioDialer:          stdioDialer,
		streamableHTTPDialer: NewStreamableHTTPDialer(),
	}
}

// NewCompositeDialerWithStreamable creates a CompositeDialer with an explicit Streamable HTTP dialer.
func NewCompositeDialerWithStreamable(httpDialer, stdioDialer, streamableHTTPDialer Dialer) *CompositeDialer {
	cd := NewCompositeDialer(httpDialer, stdioDialer)
	if streamableHTTPDialer != nil {
		cd.streamableHTTPDialer = streamableHTTPDialer
	}
	return cd
}

// Dial routes connection establishment to the appropriate dialer.
func (d *CompositeDialer) Dial(ctx context.Context, proto agent.ProtocolConfig, eventCh chan<- SSEEvent, clientSessionID string, headers http.Header) *UpstreamSession {
	if proto.IsStdio() {
		return d.stdioDialer.Dial(ctx, proto, eventCh, clientSessionID, headers)
	}
	if proto.IsStreamableHTTP() {
		return d.streamableHTTPDialer.Dial(ctx, proto, eventCh, clientSessionID, headers)
	}
	upSess := d.httpDialer.Dial(ctx, proto, eventCh, clientSessionID, headers)
	if upSess != nil && upSess.GetStatus() == "DEGRADED" && d.streamableHTTPDialer != nil {
		// Adaptive Remote Transport Fallback (ADR-0046):
		// If SSE dial resulted in DEGRADED due to HTTP 405 Method Not Allowed (server only accepts POST for JSON-RPC),
		// attempt transparent fallback to Streamable HTTP transport.
		// Never fall back if the remote server was unreachable, connection refused, or timed out.
		if upSess.LastDialStatusCode() == http.StatusMethodNotAllowed {
			slog.Info("SSE dial degraded (HTTP 405); attempting Adaptive Remote Transport fallback to Streamable HTTP",
				slog.String("protocol", proto.Name),
				slog.String("url", proto.URLOrCommand),
			)
			fallbackSess := d.streamableHTTPDialer.Dial(ctx, proto, eventCh, clientSessionID, headers)
			if fallbackSess != nil && fallbackSess.GetStatus() == "READY" {
				slog.Info("Adaptive Remote Transport fallback succeeded (upgraded to Streamable HTTP)",
					slog.String("protocol", proto.Name),
				)
				return fallbackSess
			}
		}
	}
	return upSess
}

// buildSafeSubprocessEnv constructs a minimal, sanitized execution environment
// for child stdio MCP processes. It eliminates host secret leakage (such as API_KEY,
// ADMIN_API_KEY, FARADAI_WIRE_HMAC_SECRET, and host cloud credentials) by strictly whitelisting
// standard runtime fundamentals and appending caller-specified protocol overrides.
func buildSafeSubprocessEnv(protoEnv []string) []string {
	var baseKeys []string
	if runtime.GOOS == "windows" {
		baseKeys = []string{
			"PATH", "Path", "SYSTEMROOT", "SystemRoot", "WINDIR", "windir",
			"USERPROFILE", "USERNAME", "TEMP", "TMP", "COMSPEC",
		}
	} else {
		baseKeys = []string{
			"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "SHELL",
		}
	}

	safeEnv := make([]string, 0, len(baseKeys)+len(protoEnv)+2)
	seen := make(map[string]struct{}, len(baseKeys))

	for _, k := range baseKeys {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			safeEnv = append(safeEnv, k+"="+v)
			seen[k] = struct{}{}
		}
	}

	// Guarantee TMPDIR / TEMP exists if not already present in the environment
	if _, ok := seen["TMPDIR"]; !ok && runtime.GOOS != "windows" {
		safeEnv = append(safeEnv, "TMPDIR="+os.TempDir())
	}
	if _, ok := seen["TEMP"]; !ok && runtime.GOOS == "windows" {
		safeEnv = append(safeEnv, "TEMP="+os.TempDir())
	}

	// Forward standard Go test helper process flags if present
	for _, testKey := range []string{"GO_WANT_HELPER_PROCESS", "MOCK_MODE"} {
		if v, ok := os.LookupEnv(testKey); ok && v != "" {
			safeEnv = append(safeEnv, testKey+"="+v)
		}
	}

	// Append caller-specified protocol environment overrides
	for _, env := range protoEnv {
		if trimmed := strings.TrimSpace(env); trimmed != "" {
			safeEnv = append(safeEnv, trimmed)
		}
	}

	return safeEnv
}
