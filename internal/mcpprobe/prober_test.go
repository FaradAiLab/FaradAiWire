package mcpprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestProbeStdio_StripsHostSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	t.Setenv("ADMIN_API_KEY", "canary-admin-secret-123")
	t.Setenv("API_KEY", "canary-api-secret-456")
	t.Setenv("ALLOWED_EXPLICIT_VAR", "explicit-ok-789")

	script := `
while IFS= read -r line; do
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}\n'
      ;;
    *'"tools/list"'*)
      dumped=$(env | tr '\n' '|')
      printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"env_probe","description":"%s"}]}}\n' "$dumped"
      exit 0
      ;;
  esac
done
`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools, err := ProbeStdio(ctx, StdioProbeRequest{
		Command: "sh",
		Args:    []string{"-c", script},
	})
	if err != nil {
		t.Fatalf("probe with empty env failed: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	desc, _ := tools[0]["description"].(string)
	if strings.Contains(desc, "canary-admin-secret-123") || strings.Contains(desc, "canary-api-secret-456") {
		t.Fatalf("host secrets leaked into stdio probe with empty env: %s", desc)
	}

	tools2, err := ProbeStdio(ctx, StdioProbeRequest{
		Command: "sh",
		Args:    []string{"-c", script},
		Env:     []string{"PASSED_REF=${ALLOWED_EXPLICIT_VAR}"},
	})
	if err != nil {
		t.Fatalf("probe with explicit env failed: %v", err)
	}
	desc2, _ := tools2[0]["description"].(string)
	if strings.Contains(desc2, "canary-admin-secret-123") || strings.Contains(desc2, "canary-api-secret-456") {
		t.Fatalf("host secrets leaked into stdio probe with explicit env: %s", desc2)
	}
	if !strings.Contains(desc2, "PASSED_REF=explicit-ok-789") {
		t.Fatalf("expected expanded PASSED_REF=explicit-ok-789 in probe env, got: %s", desc2)
	}
}

func TestProbeStdio_KillsGrandchildOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process group test skipped on Windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := ProbeStdio(ctx, StdioProbeRequest{
		Command: "sh",
		Args:    []string{"-c", "sleep 30 & while IFS= read -r _; do :; done"},
	})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected grandchild process group to be killed promptly, took %v", elapsed)
	}
}

func TestProbeStdio_TimeoutIncludesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err := ProbeStdio(ctx, StdioProbeRequest{
		Command: "sh",
		Args:    []string{"-c", "echo 'downloading packages...' >&2; sleep 10"},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if !strings.Contains(err.Error(), "downloading packages...") {
		t.Fatalf("expected timeout error to include stderr output, got: %v", err)
	}
}

func TestProbeStdio_StreamsStderrLines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	script := `
printf 'Downloading cpython-3.15...\rExtracting archive...\n' >&2
while IFS= read -r line; do
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}\n'
      ;;
    *'"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"demo_tool","description":"ok"}]}}\n'
      exit 0
      ;;
  esac
done
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var progress []string
	tools, err := ProbeStdio(ctx, StdioProbeRequest{
		Command: "sh",
		Args:    []string{"-c", script},
		OnProgress: func(line string) {
			mu.Lock()
			progress = append(progress, line)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("ProbeStdio failed: %v", err)
	}
	if len(tools) != 1 || tools[0]["name"] != "demo_tool" {
		t.Fatalf("unexpected tools: %#v", tools)
	}
	joined := strings.Join(progress, "\n")
	if !strings.Contains(joined, "Downloading cpython-3.15...") || !strings.Contains(joined, "Extracting archive...") {
		t.Fatalf("expected carriage-return and newline stderr lines to be streamed, got: %q", joined)
	}
}

func TestSafeBuffer_BoundsMemoryAndLineAccumulator(t *testing.T) {
	var lines []string
	buf := safeBuffer{
		onLine: func(line string) {
			lines = append(lines, line)
		},
	}

	longChunk := strings.Repeat("x", maxSafeLineBytes+500) + "\n"
	if _, err := buf.Write([]byte(longChunk)); err != nil {
		t.Fatalf("Write longChunk failed: %v", err)
	}
	if len(lines) != 1 || len(lines[0]) != maxSafeLineBytes {
		t.Fatalf("expected line accumulator capped at %d bytes, got %d lines len=%d", maxSafeLineBytes, len(lines), len(lines[0]))
	}

	heavy := strings.Repeat("A", maxSafeBufferBytes*2) + "FINAL_TAIL"
	if _, err := buf.Write([]byte(heavy)); err != nil {
		t.Fatalf("Write heavy failed: %v", err)
	}
	got := buf.String()
	if len(got) > maxSafeBufferBytes {
		t.Fatalf("expected String() capped at %d bytes, got %d", maxSafeBufferBytes, len(got))
	}
	if !strings.HasSuffix(got, "FINAL_TAIL") {
		t.Fatalf("expected String() to preserve latest tail, got suffix %q", got[len(got)-20:])
	}
}

func TestIsPackageRunnerCommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{command: "uvx", want: true},
		{command: "/usr/local/bin/npx", want: true},
		{command: `C:\Tools\uvx.exe`, want: true},
		{command: "docker", want: true},
		{command: "mcp-local-binary", want: false},
		{command: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			if got := IsPackageRunnerCommand(tc.command); got != tc.want {
				t.Fatalf("IsPackageRunnerCommand(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

func TestProbeHTTP_ValidationAndNegotiation(t *testing.T) {
	t.Run("empty target URL fails", func(t *testing.T) {
		_, err := ProbeHTTP(context.Background(), ProbeRequest{})
		if err == nil {
			t.Fatal("expected error for empty target URL")
		}
	})

	t.Run("SSRF blocks restricted targets", func(t *testing.T) {
		blocked := []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://127.0.0.1:8080/sse",
			"http://10.0.0.1/mcp",
			"file:///etc/passwd",
		}
		for _, target := range blocked {
			_, err := ProbeHTTP(context.Background(), ProbeRequest{
				TargetURL:   target,
				SSRFOptions: transport.DefaultSafeOptions(),
			})
			if err == nil {
				t.Fatalf("expected SSRF guardrail to block %s", target)
			}
		}
	})

	t.Run("SSE same-origin rejects cross-origin endpoint event", func(t *testing.T) {
		client := &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("event: endpoint\ndata: https://evil.example.org/steal\n\n")),
					}, nil
				}
				// Streamable HTTP fallback also returns 401 so we don't leak creds
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		_, err := ProbeHTTP(context.Background(), ProbeRequest{
			Client:    client,
			TargetURL: "https://trusted.example.com/sse",
			AuthToken: "secret-token",
			SSRFOptions: transport.SafeTransportOptions{
				Enabled: false,
			},
		})
		if err == nil {
			t.Fatal("expected cross-origin SSE endpoint to be rejected")
		}
	})

	t.Run("405 on SSE falls back to Streamable HTTP", func(t *testing.T) {
		var sawAuth string
		var sawBlockedHeader bool
		client := &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet {
					return &http.Response{
						StatusCode: http.StatusMethodNotAllowed,
						Status:     "405 Method Not Allowed",
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				}
				sawAuth = r.Header.Get("Authorization")
				if r.Header.Get("X-Faradaiwire-Internal") != "" || r.Header.Get("Proxy-Authorization") != "" {
					sawBlockedHeader = true
				}
				bodyBytes, _ := io.ReadAll(r.Body)
				var rpc struct {
					Method string `json:"method"`
				}
				_ = json.Unmarshal(bodyBytes, &rpc)
				switch rpc.Method {
				case "initialize":
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`)),
					}, nil
				case "notifications/initialized":
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				case "tools/list":
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"stream_tool\"}]}}\n\n")),
					}, nil
				default:
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				}
			}),
		}

		res, err := ProbeHTTP(context.Background(), ProbeRequest{
			Client:    client,
			TargetURL: "https://mcp.example.com/mcp",
			AuthToken: "my-token",
			CustomHeaders: map[string]string{
				"X-Custom":               "ok",
				"X-Faradaiwire-Internal": "spoof",
				"Proxy-Authorization":    "Basic leak",
			},
			SSRFOptions: transport.SafeTransportOptions{Enabled: false},
		})
		if err != nil {
			t.Fatalf("expected Streamable HTTP fallback to succeed, got error: %v", err)
		}
		if res.TransportMode != "streamable_http" {
			t.Fatalf("expected TransportMode streamable_http, got %q", res.TransportMode)
		}
		if len(res.Tools) != 1 || res.Tools[0]["name"] != "stream_tool" {
			t.Fatalf("unexpected discovered tools: %#v", res.Tools)
		}
		if sawAuth != "Bearer my-token" {
			t.Fatalf("expected Bearer auth header, got %q", sawAuth)
		}
		if sawBlockedHeader {
			t.Fatal("expected blocked upstream hop-by-hop/spoofing headers to be stripped")
		}
	})

	t.Run("fatal 401 on SSE does not fall back to Streamable HTTP", func(t *testing.T) {
		var postAttempted bool
		client := &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodPost {
					postAttempted = true
				}
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Status:     "401 Unauthorized",
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		}

		_, err := ProbeHTTP(context.Background(), ProbeRequest{
			Client:      client,
			TargetURL:   "https://mcp.example.com/sse",
			SSRFOptions: transport.SafeTransportOptions{Enabled: false},
		})
		var upstreamErr *UpstreamHTTPError
		if !errors.As(err, &upstreamErr) {
			t.Fatalf("expected *UpstreamHTTPError, got %v", err)
		}
		if upstreamErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", upstreamErr.StatusCode)
		}
		if postAttempted {
			t.Fatal("expected fatal 401 SSE error not to attempt Streamable HTTP POST")
		}
	})
}

func TestUpstreamHTTPError_AndRemediation(t *testing.T) {
	err := &UpstreamHTTPError{
		StatusCode:  403,
		Category:    "UPSTREAM_HTTP_ERROR",
		Remediation: "Access denied by remote server.",
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "HTTP 403") || !strings.Contains(errStr, "Forbidden") {
		t.Fatalf("unexpected Error() formatting: %s", errStr)
	}

	codes := []int{401, 403, 404, 405, 429, 500, 502, 503, 504, 418}
	for _, code := range codes {
		if msg := upstreamHTTPRemediation(code); msg == "" {
			t.Fatalf("empty remediation for status %d", code)
		}
	}
	if !bytes.Equal(extractJSONFromSSEOrDirect([]byte("data: {\"ok\":true}\n")), []byte(`{"ok":true}`)) {
		t.Fatal("expected extractJSONFromSSEOrDirect to unwrap SSE data line")
	}
	if msg := fmt.Sprintf("%s", formatStdioTimeoutError("uvx", context.DeadlineExceeded, "")); !strings.Contains(msg, "uvx") {
		t.Fatalf("unexpected timeout formatting: %s", msg)
	}
}

func TestExtractJSONFromSSEOrDirect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "direct JSON",
			input:    `{"jsonrpc":"2.0","id":1,"result":{}}`,
			expected: `{"jsonrpc":"2.0","id":1,"result":{}}`,
		},
		{
			name:     "SSE wrapped",
			input:    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
			expected: `{"jsonrpc":"2.0","id":1,"result":{}}`,
		},
		{
			name:     "SSE with multiple lines",
			input:    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\nevent: done\ndata: {}\n\n",
			expected: `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := string(extractJSONFromSSEOrDirect([]byte(tc.input)))
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
