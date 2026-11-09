package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

// executeConnect establishes a thin stdio-to-HTTP/SSE bridge to the FaradAiWire gateway daemon.
// It binds no ports, acquires no locks, and auto-spawns the daemon detachedly if offline.
func executeConnect(profile string, host string, port int, token string, noSpawn bool, in io.Reader, out io.Writer) int {
	if profile == "" {
		profile = "default"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 8090
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Healthcheck to verify if daemon is active
	if !isDaemonHealthy(host, port) {
		if noSpawn {
			fmt.Fprintf(os.Stderr, "Error: FaradAiWire daemon is not running on %s:%d\n", host, port)
			return 1
		}

		if err := spawnDetachedDaemon(host, port); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to auto-spawn FaradAiWire daemon: %v\n", err)
			return 1
		}
	}

	// 2. Resolve token if not explicitly provided
	if token == "" {
		token = resolveActiveToken(profile)
	}

	// 3. Run the stdio <-> SSE bidirectional bridge
	if err := runBridge(ctx, profile, host, port, token, in, out); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Bridge error: %v\n", err)
		return 1
	}

	return 0
}

func isDaemonHealthy(host string, port int) bool {
	client := &http.Client{Timeout: 150 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/health", host, port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func spawnDetachedDaemon(host string, port int) error {
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
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open daemon log file '%s': %w", logFilePath, err)
	}

	cmd := exec.Command(binPath, "run")
	// Strict stdout/stderr redirection: prevent ANY logs/banners from corrupting IDE stdio stream
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Detach process group so closing IDE doesn't kill shared daemon
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
	}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start detached daemon: %w", err)
	}

	_ = logFile.Close()
	_ = cmd.Process.Release()

	// Poll healthcheck up to 3000ms with 100ms intervals
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if isDaemonHealthy(host, port) {
			return nil
		}
	}

	return fmt.Errorf("daemon failed to respond to /health on %s:%d within 3s (inspect %s)", host, port, logFilePath)
}

func resolveActiveToken(profile string) string {
	keyStorePath := (&config.Config{}).GetAPIKeysPath()
	ks, err := auth.NewFileKeyStore(keyStorePath)
	if err != nil {
		return ""
	}

	keys := ks.ListKeys()
	for _, k := range keys {
		if !k.Revoked && (k.AgentName == profile || k.AgentName == "*") && k.RawKey != "" {
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

	sseURL := fmt.Sprintf("http://%s:%d/sse/%s", host, port, profile)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to gateway SSE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned HTTP %d on %s", resp.StatusCode, sseURL)
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
				errCh <- err
				return
			}

			trimmed := strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(trimmed, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			} else if strings.HasPrefix(trimmed, "data:") {
				dataVal := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if currentEvent == "endpoint" {
					select {
					case endpointCh <- dataVal:
					default:
					}
				} else if currentEvent == "message" || strings.HasPrefix(dataVal, "{") {
					// Forward JSON-RPC message directly to IDE stdout
					_, _ = fmt.Fprintln(out, dataVal)
					if flusher, ok := out.(interface{ Flush() error }); ok {
						_ = flusher.Flush()
					}
				}
				currentEvent = ""
			}
		}
	}()

	// Wait for the "event: endpoint" handshake
	var postURLStr string
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("error reading initial SSE handshake: %w", err)
	case endpoint := <-endpointCh:
		base, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, port))
		rel, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint URL '%s': %w", endpoint, err)
		}
		postURLStr = base.ResolveReference(rel).String()
	case <-time.After(5 * time.Second):
		return errors.New("timed out waiting for SSE 'event: endpoint'")
	}

	// Goroutine 2: Read host stdin line by line and POST to postURL
	stdinScanner := bufio.NewScanner(in)
	stdinDone := make(chan struct{})

	go func() {
		defer close(stdinDone)
		for stdinScanner.Scan() {
			line := stdinScanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}

			// Forward JSON-RPC call to gateway
			pReq, pErr := http.NewRequestWithContext(ctx, http.MethodPost, postURLStr, bytes.NewReader(line))
			if pErr != nil {
				continue
			}
			pReq.Header.Set("Content-Type", "application/json")
			if token != "" {
				pReq.Header.Set("Authorization", "Bearer "+token)
			}

			pResp, pErr := client.Do(pReq)
			if pErr == nil {
				_ = pResp.Body.Close()
			}
		}
		if scanErr := stdinScanner.Err(); scanErr != nil {
			errCh <- scanErr
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stdinDone:
		return nil
	case err := <-errCh:
		return err
	}
}
