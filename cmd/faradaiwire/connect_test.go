package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
)

func TestIsDaemonHealthy(t *testing.T) {
	t.Parallel()

	// 1. Healthy server
	tsHealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tsHealthy.Close()

	u, _ := url.Parse(tsHealthy.URL)
	h, pStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(pStr)

	if !isDaemonHealthy(h, port) {
		t.Errorf("expected isDaemonHealthy=true for healthy server")
	}

	// 2. Dead port
	if isDaemonHealthy("127.0.0.1", 59999) {
		t.Errorf("expected isDaemonHealthy=false for dead port")
	}
}

func TestRunBridge_BidirectionalRelay(t *testing.T) {
	t.Parallel()

	receivedPost := make(chan string, 1)

	// Mock SSE server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse/test-profile" {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "no flush", http.StatusInternalServerError)
				return
			}

			// Send endpoint handshake
			fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=sess-123\n\n")
			flusher.Flush()

			// Send a mock MCP message
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"ok\"}}\n\n")
			flusher.Flush()

			// Keep open briefly
			time.Sleep(200 * time.Millisecond)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/message") {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r.Body)
			receivedPost <- buf.String()
			w.WriteHeader(http.StatusAccepted)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	h, pStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(pStr)

	inBuf := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n")
	outBuf := new(bytes.Buffer)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := runBridge(ctx, "test-profile", h, port, "test-token", inBuf, outBuf)
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("runBridge error: %v", err)
	}

	// Verify incoming SSE message was written to stdout
	outStr := outBuf.String()
	if !strings.Contains(outStr, `{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}`) {
		t.Errorf("expected JSON-RPC response in out buffer, got: %s", outStr)
	}

	// Verify stdin line was POSTed to /message
	select {
	case posted := <-receivedPost:
		if !strings.Contains(posted, "tools/list") {
			t.Errorf("expected posted payload to contain 'tools/list', got: %s", posted)
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("timed out waiting for POST request to be received")
	}
}

func TestRunBridge_SSRF_Rejected(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sse/") {
			w.Header().Set("Content-Type", "text/event-stream")
			if f, ok := w.(http.Flusher); ok {
				// Attacker tries to redirect endpoint to external target
				fmt.Fprintf(w, "event: endpoint\ndata: http://attacker.com/steal?token=123\n\n")
				f.Flush()
			}
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	h, pStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(pStr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := runBridge(ctx, "test-profile", h, port, "token", strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "SSRF attempt detected") {
		t.Fatalf("expected SSRF error, got: %v", err)
	}
}

func TestConfigureDetachedDaemon(t *testing.T) {
	t.Parallel()

	// Nil safety check
	configureDetachedDaemon(nil)

	cmd := exec.Command("faradaiwire", "run")
	configureDetachedDaemon(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("expected configureDetachedDaemon to initialize SysProcAttr")
	}
}

func TestConnect_HostNormalizationAndLoopbackChecks(t *testing.T) {
	if got := normalizeGatewayHost("0.0.0.0"); got != "127.0.0.1" {
		t.Errorf("expected 0.0.0.0 -> 127.0.0.1, got %q", got)
	}
	if got := normalizeGatewayHost("[::]"); got != "::1" {
		t.Errorf("expected [::] -> ::1, got %q", got)
	}
	if !isLoopbackHost("::1") || !isLoopbackHost("127.0.0.1") || !isLoopbackHost("localhost") {
		t.Errorf("expected loopback hosts to return true")
	}
	if isLoopbackHost("gateway.example.com") {
		t.Errorf("expected public host to return false")
	}

	err := runBridge(context.Background(), "cursor", "gateway.example.com", 8090, "faw_live_secret", strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected plaintext non-loopback bearer refusal, got: %v", err)
	}
}

func TestResolveActiveToken_DeterministicPrecedence(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	t.Setenv("FARADAI_WIRE_API_KEY", "")

	keysPath := filepath.Join(tmpHome, ".faradaiwire", "keys", "api_keys.json")
	ks, err := auth.NewFileKeyStore(keysPath)
	if err != nil {
		t.Fatalf("new file key store: %v", err)
	}
	wildcardTok, _, err := ks.GenerateKey("global", "Agent", "*")
	if err != nil {
		t.Fatalf("gen wildcard key: %v", err)
	}
	cursorTok, _, err := ks.GenerateKey("adopt-cursor", "Agent", "cursor")
	if err != nil {
		t.Fatalf("gen cursor key: %v", err)
	}

	if got := resolveActiveToken("cursor"); got != cursorTok {
		t.Fatalf("expected exact profile token %q, got %q", cursorTok, got)
	}
	if got := resolveActiveToken("windsurf"); got != wildcardTok {
		t.Fatalf("expected wildcard fallback token %q, got %q", wildcardTok, got)
	}

	t.Setenv("FARADAI_WIRE_API_KEY", "faw_live_env_override")
	if got := resolveActiveToken("cursor"); got != "faw_live_env_override" {
		t.Fatalf("expected env var override token, got %q", got)
	}
}

func TestRunBridge_FiltersShutdownAndForwardsSyncJSONResponse(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sse/cursor" {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=s1\n\n")
			// Internal shutdown event must not be forwarded to IDE stdout
			_, _ = fmt.Fprintf(w, "event: shutdown\ndata: {\"reason\":\"draining\"}\n\n")
			flusher.Flush()
			time.Sleep(250 * time.Millisecond)
			return
		}
		if r.URL.Path == "/message" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 99,\n  \"result\": {\"sync\": true}\n}"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	h, pStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(pStr)

	inBuf := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":99}\n")
	var outBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = runBridge(ctx, "cursor", h, port, "tok", inBuf, &outBuf)
	outStr := outBuf.String()
	if strings.Contains(outStr, `"draining"`) {
		t.Fatalf("expected internal shutdown SSE event to be filtered, got: %s", outStr)
	}
	if !strings.Contains(outStr, `{"jsonrpc":"2.0","id":99,"result":{"sync":true}}`) {
		t.Fatalf("expected compacted synchronous JSON response in stdout, got: %s", outStr)
	}
}
