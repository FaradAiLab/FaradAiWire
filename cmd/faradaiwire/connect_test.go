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
	"strconv"
	"strings"
	"testing"
	"time"
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
