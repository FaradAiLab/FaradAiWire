package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProbeAndDiscoverMCPToolsStdio_StripsHostSecrets(t *testing.T) {
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

	// Case 1: empty env must still sanitize host secrets (must not inherit os.Environ)
	tools, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", script}, nil)
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

	// Case 2: explicit ${VAR} ref is expanded while unrelated host secrets stay absent
	tools2, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", script}, []string{"PASSED_REF=${ALLOWED_EXPLICIT_VAR}"})
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

func TestProbeAndDiscoverMCPToolsStdio_KillsGrandchildOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process group test skipped on Windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	// Spawn a grandchild sleep holding stdout open while parent drains stdin without replying
	_, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", "sleep 30 & while IFS= read -r _; do :; done"}, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected grandchild process group to be killed promptly, took %v", elapsed)
	}
}

func TestProbeAndDiscoverMCPToolsStdio_TimeoutIncludesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err := ProbeAndDiscoverMCPToolsStdio(ctx, "sh", []string{"-c", "echo 'downloading packages...' >&2; sleep 10"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	if !strings.Contains(err.Error(), "downloading packages...") {
		t.Fatalf("expected timeout error to include stderr output, got: %v", err)
	}
}

func TestStdioProbeTimeout_FloorsByCommandType(t *testing.T) {
	s := NewAdminServer(nil, nil, nil)
	if got := s.probeTimeout(); got != 5*time.Second {
		t.Fatalf("expected default probeTimeout=5s, got %v", got)
	}
	if got := s.stdioProbeTimeout("mcp-local-binary"); got != 30*time.Second {
		t.Fatalf("expected default stdioProbeTimeout=30s, got %v", got)
	}
	if got := s.stdioProbeTimeout("uvx"); got != 120*time.Second {
		t.Fatalf("expected uvx stdioProbeTimeout=120s, got %v", got)
	}
	if got := s.stdioProbeTimeout(`C:\Tools\uvx.exe`); got != 120*time.Second {
		t.Fatalf("expected Windows uvx.exe stdioProbeTimeout=120s, got %v", got)
	}
}

func TestProbeAndDiscoverMCPToolsStdioWithProgress_StreamsStderrLines(t *testing.T) {
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
	tools, err := ProbeAndDiscoverMCPToolsStdioWithProgress(ctx, "sh", []string{"-c", script}, nil, func(line string) {
		mu.Lock()
		progress = append(progress, line)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("ProbeAndDiscoverMCPToolsStdioWithProgress failed: %v", err)
	}
	if len(tools) != 1 || tools[0]["name"] != "demo_tool" {
		t.Fatalf("unexpected tools: %#v", tools)
	}
	joined := strings.Join(progress, "\n")
	if !strings.Contains(joined, "Downloading cpython-3.15...") || !strings.Contains(joined, "Extracting archive...") {
		t.Fatalf("expected carriage-return and newline stderr lines to be streamed, got: %q", joined)
	}
}

func TestHandleProtocolProbe_StreamSSE(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	script := `
printf 'Installing mcp-server-git...\n' >&2
while IFS= read -r line; do
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}\n'
      ;;
    *'"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"git_status","description":"status"}]}}\n'
      exit 0
      ;;
  esac
done
`
	payload, err := json.Marshal(ProbeProtocolRequest{
		Type:    "stdio",
		Command: "sh",
		Args:    []string{"-c", script},
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe?stream=1", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s := NewAdminServer(nil, nil, nil)
	s.handleProtocolProbe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream Content-Type, got %q", ct)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: progress\n") {
		t.Fatalf("expected SSE progress event in body: %s", out)
	}
	if !strings.Contains(out, "Installing mcp-server-git...") {
		t.Fatalf("expected stderr line in SSE progress event: %s", out)
	}
	if !strings.Contains(out, "event: result\n") || !strings.Contains(out, `"git_status"`) {
		t.Fatalf("expected SSE result event with discovered tool in body: %s", out)
	}
}

func TestHandleProtocolProbe_StreamSSE_ErrorEvent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test skipped on Windows")
	}

	payload, err := json.Marshal(ProbeProtocolRequest{
		Type:    "stdio",
		Command: "sh",
		Args:    []string{"-c", "printf 'Downloading packages...\n' >&2; exit 2"},
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/protocols/probe?stream=1", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s := NewAdminServer(nil, nil, nil)
	s.handleProtocolProbe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK SSE stream header, got %d: %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: progress\n") || !strings.Contains(out, "Downloading packages...") {
		t.Fatalf("expected SSE progress line before failure, got: %s", out)
	}
	if !strings.Contains(out, "event: error\n") || !strings.Contains(out, `"PROBE_FAILED"`) {
		t.Fatalf("expected SSE error event with PROBE_FAILED, got: %s", out)
	}
}

func TestSafeBuffer_BoundsMemoryAndLineAccumulator(t *testing.T) {
	var lines []string
	buf := safeBuffer{
		onLine: func(line string) {
			lines = append(lines, line)
		},
	}

	// Write a very long line without newlines (exceeds maxSafeLineBytes) followed by newline
	longChunk := strings.Repeat("x", maxSafeLineBytes+500) + "\n"
	if _, err := buf.Write([]byte(longChunk)); err != nil {
		t.Fatalf("Write longChunk failed: %v", err)
	}
	if len(lines) != 1 || len(lines[0]) != maxSafeLineBytes {
		t.Fatalf("expected line accumulator capped at %d bytes, got %d lines len=%d", maxSafeLineBytes, len(lines), len(lines[0]))
	}

	// Write more than 2*maxSafeBufferBytes and confirm String() retains bounded tail
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
