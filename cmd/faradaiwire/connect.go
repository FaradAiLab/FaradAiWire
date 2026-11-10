package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func blockRedirects(*http.Request, []*http.Request) error {
	return errors.New("redirects are disallowed on gateway connection")
}

var healthCheckHTTPClient = &http.Client{
	Timeout:       150 * time.Millisecond,
	CheckRedirect: blockRedirects,
}

func normalizeGatewayHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	switch h {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	default:
		return h
	}
}

func isLoopbackHost(host string) bool {
	h := normalizeGatewayHost(host)
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// executeConnect establishes a thin stdio-to-HTTP/SSE bridge to the FaradAiWire gateway daemon.
// It binds no ports, acquires no locks, and auto-spawns the daemon detachedly if offline.
func executeConnect(profile string, host string, port int, token string, noSpawn bool, in io.Reader, out io.Writer) int {
	if profile == "" {
		profile = "default"
	}
	host = normalizeGatewayHost(host)
	if port <= 0 {
		port = 8090
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Healthcheck to verify if daemon is active
	if !isDaemonHealthy(host, port) {
		if noSpawn {
			fmt.Fprintf(os.Stderr, "Error: FaradAiWire daemon is not running on %s\n", net.JoinHostPort(host, strconv.Itoa(port)))
			return 1
		}

		if err := spawnDetachedDaemon(ctx, host, port); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to auto-spawn FaradAiWire daemon: %v\n", err)
			return 1
		}
	}

	// 2. Resolve token if not explicitly provided
	if token == "" {
		token = resolveActiveToken(profile)
	}
	if token != "" && !isLoopbackHost(host) {
		fmt.Fprintf(os.Stderr, "Error: refusing to send bearer token over unencrypted http:// to non-loopback host %q\n", host)
		return 1
	}

	// 3. Run the stdio <-> SSE bidirectional bridge
	if err := runBridge(ctx, profile, host, port, token, in, out); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Bridge error: %v\n", err)
		return 1
	}

	return 0
}

func isDaemonHealthy(host string, port int) bool {
	target := net.JoinHostPort(normalizeGatewayHost(host), strconv.Itoa(port))
	resp, err := healthCheckHTTPClient.Get("http://" + target + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	return resp.StatusCode == http.StatusOK
}

func spawnDetachedDaemon(ctx context.Context, host string, port int) error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// Ensure logs directory exists
	homeDir := config.DefaultFaradAiWireDir()
	logsDir := filepath.Join(homeDir, "logs")
	if err := os.MkdirAll(logsDir, 0700); err != nil {
		logsDir = "./logs"
		_ = os.MkdirAll(logsDir, 0700)
	}

	logFilePath := filepath.Join(logsDir, "daemon.log")
	// Enforce 0600 permissions to protect daemon log files containing connection info
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open daemon log file '%s': %w", logFilePath, err)
	}

	args := []string{"run"}
	if h := normalizeGatewayHost(host); h != "" {
		args = append(args, "-host", h)
	}
	if port > 0 {
		args = append(args, "-port", strconv.Itoa(port))
	}
	cmd := exec.Command(binPath, args...)
	// Strict stdout/stderr redirection: prevent ANY logs/banners from corrupting IDE stdio stream
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Detach process group so closing IDE doesn't kill shared daemon
	configureDetachedDaemon(cmd)

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start detached daemon: %w", err)
	}

	_ = logFile.Close()
	// Reap daemon asynchronously if it exits while connect stays open so no zombie accumulates
	go func() {
		_ = cmd.Wait()
	}()

	// Poll healthcheck up to 3000ms with 100ms intervals respecting context cancellation
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if isDaemonHealthy(host, port) {
				return nil
			}
		}
	}

	return fmt.Errorf("daemon failed to respond to /health on %s within 3s (inspect %s)", net.JoinHostPort(normalizeGatewayHost(host), strconv.Itoa(port)), logFilePath)
}

func resolveActiveToken(profile string) string {
	if envTok := strings.TrimSpace(os.Getenv("FARADAI_WIRE_API_KEY")); envTok != "" {
		return envTok
	}

	keyStorePath := (&config.Config{}).GetAPIKeysPath()
	ks, err := auth.NewFileKeyStore(keyStorePath)
	if err != nil {
		return ""
	}

	keys := ks.ListKeys()
	sort.Slice(keys, func(i, j int) bool {
		if !keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].CreatedAt.After(keys[j].CreatedAt)
		}
		return keys[i].ID < keys[j].ID
	})

	for _, k := range keys {
		if !k.Revoked && k.RawKey != "" && strings.EqualFold(k.AgentName, profile) {
			return k.RawKey
		}
	}
	for _, k := range keys {
		if !k.Revoked && k.RawKey != "" && k.AgentName == "*" {
			return k.RawKey
		}
	}
	return ""
}

func runBridge(ctx context.Context, profile, host string, port int, token string, in io.Reader, out io.Writer) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	host = normalizeGatewayHost(host)
	if token != "" && !isLoopbackHost(host) {
		return fmt.Errorf("refusing to send bearer token over unencrypted http:// to non-loopback host %q", host)
	}

	bridgeCtx, bridgeCancel := context.WithCancel(ctx)
	defer bridgeCancel()

	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	baseURLStr := "http://" + hostPort
	sseURL := fmt.Sprintf("%s/sse/%s", baseURLStr, url.PathEscape(profile))
	req, err := http.NewRequestWithContext(bridgeCtx, http.MethodGet, sseURL, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	sseClient := &http.Client{
		Timeout:       0,
		CheckRedirect: blockRedirects,
	}
	resp, err := sseClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect to gateway SSE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned HTTP %d on %s", resp.StatusCode, sseURL)
	}

	// Guarantee that closing the response unblocks any blocking read when bridgeCtx cancels
	go func() {
		<-bridgeCtx.Done()
		_ = resp.Body.Close()
	}()

	var outMu sync.Mutex
	writeOutputLine := func(line string) {
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = fmt.Fprintln(out, line)
		if flusher, ok := out.(interface{ Flush() error }); ok {
			_ = flusher.Flush()
		}
	}

	reader := bufio.NewReader(resp.Body)
	endpointCh := make(chan string, 1)
	errCh := make(chan error, 2)

	// Goroutine 1: Read SSE stream and write messages to out
	go func() {
		var currentEvent string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				select {
				case <-bridgeCtx.Done():
					return
				default:
					errCh <- err
					return
				}
			}

			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				currentEvent = ""
				continue
			}
			if strings.HasPrefix(trimmed, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			} else if strings.HasPrefix(trimmed, "data:") {
				dataVal := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if currentEvent == "endpoint" {
					select {
					case endpointCh <- dataVal:
					default:
					}
				} else if currentEvent == "shutdown" {
					// Internal gateway shutdown notification must not pollute JSON-RPC stdout
				} else if currentEvent == "message" || (currentEvent == "" && strings.HasPrefix(dataVal, "{")) {
					writeOutputLine(dataVal)
				}
				currentEvent = ""
			}
		}
	}()

	// Wait for the "event: endpoint" handshake
	var postURLStr string
	select {
	case <-bridgeCtx.Done():
		return bridgeCtx.Err()
	case err := <-errCh:
		return fmt.Errorf("error reading initial SSE handshake: %w", err)
	case endpoint := <-endpointCh:
		base, parseErr := url.Parse(baseURLStr)
		if parseErr != nil {
			return fmt.Errorf("invalid gateway base URL %q: %w", baseURLStr, parseErr)
		}
		rel, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint URL '%s': %w", endpoint, err)
		}
		resolved := base.ResolveReference(rel)
		if resolved.User != nil {
			return errors.New("SSRF attempt detected: endpoint URL must not embed credentials")
		}
		// Security: Prevent SSRF / token exfiltration by strictly validating host and scheme
		if resolved.Host != base.Host || resolved.Scheme != base.Scheme {
			return fmt.Errorf("SSRF attempt detected: endpoint host '%s' must match gateway host '%s'", resolved.Host, base.Host)
		}
		postURLStr = resolved.String()
	case <-time.After(5 * time.Second):
		return errors.New("timed out waiting for SSE 'event: endpoint'")
	}

	// Setup dedicated connection-pooled HTTP client with 30s timeout for POST requests
	postTransport := &http.Transport{
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
	defer postTransport.CloseIdleConnections()
	postClient := &http.Client{
		Transport:     postTransport,
		Timeout:       30 * time.Second,
		CheckRedirect: blockRedirects,
	}

	// Goroutine 2: Read host stdin line by line and POST to postURL
	stdinScanner := bufio.NewScanner(in)
	// Support up to 10MB token size for large MCP write_file/schema payloads
	stdinScanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	stdinDone := make(chan struct{})

	go func() {
		defer close(stdinDone)
		for stdinScanner.Scan() {
			line := stdinScanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}

			// Forward JSON-RPC call to gateway
			pReq, pErr := http.NewRequestWithContext(bridgeCtx, http.MethodPost, postURLStr, bytes.NewReader(line))
			if pErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "[faradaiwire connect] failed to construct POST request: %v\n", pErr)
				continue
			}
			pReq.Header.Set("Content-Type", "application/json")
			if token != "" {
				pReq.Header.Set("Authorization", "Bearer "+token)
			}

			pResp, pErr := postClient.Do(pReq)
			if pErr != nil {
				if bridgeCtx.Err() != nil {
					return
				}
				_, _ = fmt.Fprintf(os.Stderr, "[faradaiwire connect] gateway POST error: %v\n", pErr)
				continue
			}

			ct := strings.ToLower(pResp.Header.Get("Content-Type"))
			if pResp.StatusCode == http.StatusUnauthorized || pResp.StatusCode == http.StatusForbidden {
				_, _ = io.Copy(io.Discard, io.LimitReader(pResp.Body, 4096))
				_ = pResp.Body.Close()
				select {
				case errCh <- fmt.Errorf("gateway rejected POST message with HTTP %d", pResp.StatusCode):
				default:
				}
				return
			}
			if strings.Contains(ct, "application/json") {
				rawBody, readErr := io.ReadAll(io.LimitReader(pResp.Body, 10<<20))
				_ = pResp.Body.Close()
				if readErr != nil {
					_, _ = fmt.Fprintf(os.Stderr, "[faradaiwire connect] failed to read gateway JSON response: %v\n", readErr)
					continue
				}
				trimmedBody := bytes.TrimSpace(rawBody)
				if len(trimmedBody) > 0 && (trimmedBody[0] == '{' || trimmedBody[0] == '[') {
					var compact bytes.Buffer
					if cErr := json.Compact(&compact, trimmedBody); cErr == nil {
						writeOutputLine(compact.String())
					} else {
						_, _ = fmt.Fprintf(os.Stderr, "[faradaiwire connect] invalid JSON response from gateway: %v\n", cErr)
					}
				}
			} else {
				if pResp.StatusCode >= http.StatusBadRequest {
					_, _ = fmt.Fprintf(os.Stderr, "[faradaiwire connect] gateway POST returned HTTP %d\n", pResp.StatusCode)
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(pResp.Body, 4096))
				_ = pResp.Body.Close()
			}
		}
		if scanErr := stdinScanner.Err(); scanErr != nil {
			select {
			case <-bridgeCtx.Done():
				return
			default:
				errCh <- scanErr
			}
		}
	}()

	select {
	case <-bridgeCtx.Done():
		return bridgeCtx.Err()
	case <-stdinDone:
		return nil
	case err := <-errCh:
		return err
	}
}
