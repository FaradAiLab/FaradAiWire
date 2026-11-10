package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

type syncBuffer struct {
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (n int, err error) {
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	return b.buf.String()
}

func TestStdioProxy_EndToEnd_RequestResponse(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "normal")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		false,
		nil,
		config.UserContextConfig{FallbackUser: "dev", FallbackRole: "Engineer"},
		inReader,
		outWriter,
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- p.Start(ctx)
	}()

	// Send a JSON-RPC tool call request
	req := `{"jsonrpc":"2.0","id":"test-call-1","method":"tools/call","params":{"name":"echo","arguments":{}}}`
	_, err := inWriter.Write([]byte(req + "\n"))
	if err != nil {
		t.Fatalf("failed to write request to proxy: %v", err)
	}

	// Read response from proxy output
	outScanner := bufio.NewScanner(outReader)
	respCh := make(chan string, 1)
	go func() {
		if outScanner.Scan() {
			respCh <- outScanner.Text()
		}
	}()

	select {
	case line := <-respCh:
		var resp mcp.Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("malformed response: %v, raw: %s", err, line)
		}
		if resp.ID != "test-call-1" {
			t.Errorf("expected resp.ID 'test-call-1', got: %v", resp.ID)
		}
		if !strings.Contains(string(resp.Result), "local stdio execution output") {
			t.Errorf("unexpected result: %s", string(resp.Result))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for response from StdioProxy")
	}

	// Close client stdin to trigger graceful shutdown
	_ = inWriter.Close()

	select {
	case err := <-startErrCh:
		if err != nil {
			t.Errorf("expected clean exit on stdin EOF, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("StdioProxy did not exit after stdin EOF")
	}
}

func TestStdioProxy_ServerNotificationForwarding(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "notify_before_response")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		false,
		nil,
		config.UserContextConfig{},
		inReader,
		outWriter,
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = p.Start(ctx)
	}()

	req := `{"jsonrpc":"2.0","id":"notify-call-1","method":"tools/call","params":{"name":"echo"}}`
	_, _ = inWriter.Write([]byte(req + "\n"))

	outScanner := bufio.NewScanner(outReader)
	lines := make([]string, 0, 2)
	doneCh := make(chan struct{})

	go func() {
		for outScanner.Scan() {
			lines = append(lines, outScanner.Text())
			if len(lines) == 2 {
				close(doneCh)
				return
			}
		}
	}()

	select {
	case <-doneCh:
		// Expect one notification and one response
		joined := strings.Join(lines, " ")
		if !strings.Contains(joined, "notifications/test") {
			t.Errorf("expected server notification in output, got: %v", lines)
		}
		if !strings.Contains(joined, "notify-call-1") {
			t.Errorf("expected response in output, got: %v", lines)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for notification + response, received lines: %v", lines)
	}

	p.Stop()
	_ = inWriter.Close()
}

type mockBlockingFilter struct{}

func (m *mockBlockingFilter) Name() string { return "mock_blocker" }
func (m *mockBlockingFilter) FilterRequest(ctx context.Context, req *mcp.Request) (*mcp.Request, *mcp.Error) {
	return nil, mcp.NewError(mcp.ErrPolicyDenied, "blocked by policy", nil)
}

func TestStdioProxy_FilterBlockingRequest(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "normal")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}
	pipeline := filter.NewPipeline(nil)
	pipeline.SetFilters([]filter.NamedFilter{&mockBlockingFilter{}})

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		false,
		pipeline,
		config.UserContextConfig{},
		inReader,
		outWriter,
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = p.Start(ctx)
	}()

	req := `{"jsonrpc":"2.0","id":"blocked-req","method":"tools/call","params":{"name":"forbidden"}}`
	_, _ = inWriter.Write([]byte(req + "\n"))

	outScanner := bufio.NewScanner(outReader)
	respCh := make(chan string, 1)
	go func() {
		if outScanner.Scan() {
			respCh <- outScanner.Text()
		}
	}()

	select {
	case line := <-respCh:
		var resp mcp.Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("malformed response: %v", err)
		}
		if resp.Error == nil {
			t.Fatalf("expected error response from blocking filter, got success")
		}
		if resp.Error.Code != mcp.ErrPolicyDenied {
			t.Errorf("expected error code %d, got: %d", mcp.ErrPolicyDenied, resp.Error.Code)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for blocked response")
	}

	p.Stop()
	_ = inWriter.Close()
}

func TestStdioProxy_SubprocessCrash_DeadlockElimination(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "crash_on_first_request")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		false, // No auto-restart
		nil,
		config.UserContextConfig{},
		inReader, // host stdin remains OPEN!
		outWriter,
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- p.Start(ctx)
	}()

	// Trigger the crash by sending the first request
	start := time.Now()
	_, _ = inWriter.Write([]byte(`{"jsonrpc":"2.0","id":"crash-trigger","method":"tools/call"}` + "\n"))

	// Verify that Start() returns quickly and does NOT deadlock on unclosed inWriter!
	select {
	case err := <-startErrCh:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected error from StdioProxy on child crash, got nil")
		}
		t.Logf("StdioProxy cleanly exited in %v with error: %v (no deadlock on open stdin!)", elapsed, err)
		if elapsed > 1*time.Second {
			t.Errorf("StdioProxy took too long to exit: %v (> 1s)", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("DEADLOCK DETECTED: StdioProxy.Start() did not return after child process crash!")
	}

	_ = inWriter.Close()
	_ = outReader.Close()
}

func TestStdioProxy_ContextCancellation(t *testing.T) {
	inReader, inWriter := io.Pipe()
	_, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "normal")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		false,
		nil,
		config.UserContextConfig{},
		inReader,
		outWriter,
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- p.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-startErrCh:
		if err != context.Canceled {
			t.Logf("StdioProxy returned: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("StdioProxy did not terminate on context cancellation")
	}

	_ = inWriter.Close()
}

func TestStdioProxy_Stop(t *testing.T) {
	inReader, inWriter := io.Pipe()
	_, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "normal")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		true, // auto-restart true, but Stop() should override it
		nil,
		config.UserContextConfig{},
		inReader,
		outWriter,
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- p.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	p.Stop()

	select {
	case err := <-startErrCh:
		if err != nil {
			t.Errorf("expected clean exit on Stop(), got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("StdioProxy did not terminate on Stop()")
	}

	_ = inWriter.Close()
}

func TestStdioProxy_SubprocessCrash_AutoRestart(t *testing.T) {
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()

	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("MOCK_MODE", "normal")

	cmdPath := os.Args[0]
	cmdArgs := []string{"-test.run=TestHelperProcess", "--"}

	p := NewStdioProxyWithIO(
		cmdPath,
		cmdArgs,
		true, // autoRestart enabled!
		nil,
		config.UserContextConfig{},
		inReader,
		outWriter,
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- p.Start(ctx)
	}()

	// First request succeeds
	req1 := `{"jsonrpc":"2.0","id":"req-before-crash","method":"tools/call","params":{"name":"echo"}}`
	_, _ = inWriter.Write([]byte(req1 + "\n"))

	outScanner := bufio.NewScanner(outReader)
	if !outScanner.Scan() {
		t.Fatalf("failed to read first response")
	}
	t.Logf("First response: %s", outScanner.Text())

	// Kill child process directly
	p.mu.Lock()
	sess := p.currSession
	p.mu.Unlock()
	if sess != nil && sess.ProcExitCh() != nil {
		sess.Close()
	}

	// Wait 1.2s for auto-restart to complete (1s backoff)
	time.Sleep(1200 * time.Millisecond)

	// Send second request to the restarted child
	req2 := `{"jsonrpc":"2.0","id":"req-after-crash","method":"tools/call","params":{"name":"echo"}}`
	_, _ = inWriter.Write([]byte(req2 + "\n"))

	respCh := make(chan string, 1)
	go func() {
		if outScanner.Scan() {
			respCh <- outScanner.Text()
		}
	}()

	select {
	case line := <-respCh:
		var resp mcp.Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("malformed response: %v, raw: %s", err, line)
		}
		if resp.ID != "req-after-crash" {
			t.Errorf("expected resp.ID 'req-after-crash', got: %v", resp.ID)
		}
		t.Logf("Second response after auto-restart: %s", line)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for response after auto-restart")
	}

	p.Stop()
	_ = inWriter.Close()
	_ = outReader.Close()

	select {
	case err := <-startErrCh:
		if err != nil {
			t.Errorf("expected clean exit on Stop(), got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("StdioProxy did not terminate on Stop()")
	}
}
