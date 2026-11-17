//go:build !windows

package session

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

func TestStdioDialer_ProcessGroupIsolationAndTermination(t *testing.T) {
	dialer := NewStdioDialer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:           "test-proc-proto",
		Name:         "test-sleeper",
		URLOrCommand: "sleep 30",
		Type:         "stdio",
	}

	eventCh := make(chan SSEEvent, 10)
	upSess := dialer.Dial(ctx, proto, eventCh, "sess-pgid-1", nil)
	if upSess == nil {
		t.Fatalf("expected non-nil UpstreamSession")
	}

	if upSess.cmd == nil || upSess.cmd.Process == nil {
		t.Fatalf("expected valid cmd and process in UpstreamSession")
	}

	pid := upSess.cmd.Process.Pid
	if pid <= 0 {
		t.Fatalf("invalid process pid: %d", pid)
	}

	// Verify SysProcAttr has Setpgid = true
	if upSess.cmd.SysProcAttr == nil || !upSess.cmd.SysProcAttr.Setpgid {
		t.Errorf("expected SysProcAttr.Setpgid to be true")
	}

	// Verify process is alive
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("expected process %d to be alive initially: %v", pid, err)
	}

	// Close upstream session - should cleanly kill process group
	closeStart := time.Now()
	upSess.Close()
	closeDuration := time.Since(closeStart)

	if closeDuration > 50*time.Millisecond {
		t.Errorf("expected close to take <50ms, took %v", closeDuration)
	}

	if upSess.GetStatus() != "CLOSED" {
		t.Errorf("expected status CLOSED, got %s", upSess.GetStatus())
	}

	// Wait up to 500ms to verify process is reaped/terminated
	dead := false
	for i := 0; i < 10; i++ {
		if err := syscall.Kill(pid, 0); err != nil {
			dead = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !dead {
		t.Errorf("expected process %d to be dead after Close()", pid)
	}
}

func TestStdioDialer_BoundedChannelSends_NoDeadlock(t *testing.T) {
	// Subprocess emits multiple JSON-RPC notification messages to stdout
	// Event channel is unbuffered, and nobody reads from it.
	// When parent context is canceled, reader goroutine must exit promptly without deadlocking.

	dialer := NewStdioDialer()
	ctx, cancel := context.WithCancel(context.Background())

	proto := agent.ProtocolConfig{
		ID:      "test-spam-proto",
		Name:    "test-spammer",
		Command: "sh",
		Args:    []string{"-c", `while true; do echo '{"jsonrpc":"2.0","method":"notifications/test","params":{}}'; sleep 0.01; done`},
		Type:    "stdio",
	}

	// Unbuffered event channel - consumer will NOT read from this
	unbufferedEventCh := make(chan SSEEvent)

	upSess := dialer.Dial(ctx, proto, unbufferedEventCh, "sess-deadlock-test", nil)
	if upSess == nil {
		cancel()
		t.Fatalf("expected non-nil UpstreamSession")
	}

	// Give subprocess 100ms to start and attempt writing to unbuffered channel
	time.Sleep(100 * time.Millisecond)

	// Now cancel context and close session
	cancelDone := make(chan struct{})
	go func() {
		cancel()
		upSess.Close()
		close(cancelDone)
	}()

	select {
	case <-cancelDone:
		// Success: reader unblocked and closed cleanly
	case <-time.After(1 * time.Second):
		t.Fatal("deadlock detected: StdioDialer reader goroutine failed to unblock within 1s")
	}
}

func TestStdioDialer_FastGracefulTeardown_Under20ms(t *testing.T) {
	dialer := NewStdioDialer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:           "test-fast-teardown",
		Name:         "test-fast-sleeper",
		URLOrCommand: "sleep 30",
		Type:         "stdio",
	}

	upSess := dialer.Dial(ctx, proto, make(chan SSEEvent, 10), "sess-fast-1", nil)
	if upSess == nil || upSess.cmd == nil || upSess.cmd.Process == nil {
		t.Fatalf("expected active UpstreamSession with process")
	}

	pid := upSess.cmd.Process.Pid
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("process %d was not started: %v", pid, err)
	}

	start := time.Now()
	upSess.Close()
	elapsed := time.Since(start)

	// Verify channel closed deterministically
	select {
	case <-upSess.ProcExitCh():
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("procExitCh was not closed after Close()")
	}

	t.Logf("Fast graceful teardown duration: %v (PID: %d)", elapsed, pid)
	if elapsed >= 20*time.Millisecond {
		t.Errorf("expected graceful teardown in <20ms, took %v", elapsed)
	}

	// Verify process was reaped (no zombie)
	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("process %d still alive after Close()", pid)
	}
}

func TestStdioDialer_NoSpuriousSIGKILL(t *testing.T) {
	dialer := NewStdioDialer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Subprocess traps SIGTERM and exits cleanly with 0
	proto := agent.ProtocolConfig{
		ID:      "test-sigterm-trap",
		Name:    "test-traps-sigterm",
		Command: "sh",
		Args:    []string{"-c", `trap "exit 0" TERM; while true; do sleep 0.05; done`},
		Type:    "stdio",
	}

	upSess := dialer.Dial(ctx, proto, make(chan SSEEvent, 10), "sess-sigterm-1", nil)
	if upSess == nil || upSess.cmd == nil || upSess.cmd.Process == nil {
		t.Fatalf("expected active UpstreamSession")
	}

	// Wait briefly for shell to install trap
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	upSess.Close()
	elapsed := time.Since(start)

	t.Logf("Clean SIGTERM handling duration: %v", elapsed)
	if elapsed >= 100*time.Millisecond {
		t.Errorf("expected clean SIGTERM teardown in <100ms, took %v", elapsed)
	}

	// Verify process state: ExitCode must be 0, not terminated by SIGKILL (signal 9)
	ps := upSess.cmd.ProcessState
	if ps == nil {
		t.Fatalf("expected non-nil ProcessState")
	}
	if ps.ExitCode() != 0 {
		t.Errorf("expected exit code 0 from SIGTERM handler, got %d (received SIGKILL?)", ps.ExitCode())
	}
}

func TestStdioDialer_EscalationToSIGKILL_OnStubbornProcess(t *testing.T) {
	cmd := exec.Command("sh", "-c", `trap "" TERM; while true; do sleep 0.05; done`)
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start stubborn command: %v", err)
	}

	pid := cmd.Process.Pid
	procExitCh := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(procExitCh)
	}()

	// Wait briefly for trap to be installed
	time.Sleep(50 * time.Millisecond)

	// Use custom grace period of 80ms to test escalation without wasting 300ms
	gracePeriod := 80 * time.Millisecond
	start := time.Now()
	killProcessGroupWithGrace(cmd, procExitCh, gracePeriod)
	elapsed := time.Since(start)

	t.Logf("Stubborn process SIGKILL escalation took %v", elapsed)

	// Must take at least gracePeriod because it ignored SIGTERM
	if elapsed < gracePeriod {
		t.Errorf("expected escalation to wait at least %v, took %v", gracePeriod, elapsed)
	}

	// But must terminate shortly after SIGKILL
	if elapsed > 250*time.Millisecond {
		t.Errorf("expected SIGKILL termination in <250ms, took %v", elapsed)
	}

	// Verify process is dead
	select {
	case <-procExitCh:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("expected stubborn process to exit after SIGKILL")
	}

	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("process %d still alive after SIGKILL escalation", pid)
	}
}

func TestStdioDialer_ZeroZombiesInProcessTable(t *testing.T) {
	dialer := NewStdioDialer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:           "test-zombie-proto",
		Name:         "test-zombie-check",
		URLOrCommand: "sleep 10",
		Type:         "stdio",
	}

	upSess := dialer.Dial(ctx, proto, make(chan SSEEvent, 10), "sess-zombie-1", nil)
	pid := upSess.cmd.Process.Pid

	upSess.Close()

	// Wait on procExitCh
	select {
	case <-upSess.ProcExitCh():
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("procExitCh did not close")
	}

	// Query ps for process state
	out, err := exec.Command("ps", "-o", "pid,state,command", "-p", fmt.Sprintf("%d", pid)).CombinedOutput()
	outStr := string(out)
	t.Logf("ps output for PID %d (err: %v): %s", pid, err, outStr)

	// Process should either not be found (PID not in ps output) or not in zombie state 'Z'
	if strings.Contains(outStr, fmt.Sprintf("%d", pid)) {
		if strings.Contains(outStr, " Z ") || strings.Contains(outStr, "defunct") {
			t.Errorf("detected zombie/defunct process %d in ps output: %s", pid, outStr)
		}
	}
}

func BenchmarkStdioDialer_MultiProcessTeardown(b *testing.B) {
	dialer := NewStdioDialer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		const numProcs = 5
		sessions := make([]*UpstreamSession, numProcs)
		for j := 0; j < numProcs; j++ {
			proto := agent.ProtocolConfig{
				ID:           fmt.Sprintf("bench-proc-%d", j),
				Name:         fmt.Sprintf("sleeper-%d", j),
				URLOrCommand: "sleep 30",
				Type:         "stdio",
			}
			sessions[j] = dialer.Dial(context.Background(), proto, make(chan SSEEvent, 5), fmt.Sprintf("sess-bench-%d", j), nil)
		}

		b.StartTimer()
		start := time.Now()
		// Shut down all 5 processes concurrently
		var wg sync.WaitGroup
		for _, s := range sessions {
			wg.Add(1)
			go func(sess *UpstreamSession) {
				defer wg.Done()
				sess.Close()
			}(s)
		}
		wg.Wait()
		elapsed := time.Since(start)

		if elapsed > 50*time.Millisecond {
			b.Errorf("aggregate teardown of %d processes took %v (> 50ms)", numProcs, elapsed)
		}
	}
}

func TestStdioDialer_SubprocessCrash_PendingCallsFailFast(t *testing.T) {
	dialer := NewStdioDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:           "test-crash-proto",
		Name:         "test-crash-proc",
		URLOrCommand: "cat", // will block waiting on stdin/stdout
		Type:         "stdio",
	}

	upSess := dialer.Dial(ctx, proto, make(chan SSEEvent, 10), "sess-crash-1", nil)
	pid := upSess.cmd.Process.Pid
	errCh := make(chan error, 1)
	start := time.Now()

	// Launch in-flight CallTool in background goroutine
	go func() {
		req := &mcp.Request{
			JSONRPC: "2.0",
			Method:  "tools/call",
			ID:      "req-inflight-123",
		}
		_, err := upSess.CallTool(ctx, req)
		errCh <- err
	}()

	// Wait 20ms to ensure CallTool is registered and waiting in pendingCalls
	time.Sleep(20 * time.Millisecond)

	// Simulate unexpected crash / SIGKILL
	killStart := time.Now()
	_ = syscall.Kill(pid, syscall.SIGKILL)

	// Verify CallTool returns immediately
	select {
	case err := <-errCh:
		elapsed := time.Since(killStart)
		if err == nil {
			t.Fatalf("expected error from CallTool on process kill, got nil")
		}
		if elapsed > 50*time.Millisecond {
			t.Errorf("CallTool fail-fast took %v (> 50ms)", elapsed)
		}
		t.Logf("CallTool unblocked in %v with error: %v (total: %v)", elapsed, err, time.Since(start))
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("CallTool did not unblock within 500ms after SIGKILL")
	}

	// Wait for procExitCh
	select {
	case <-upSess.ProcExitCh():
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("procExitCh was not closed after SIGKILL")
	}

	// Verify subsequent calls fail fast immediately
	req := &mcp.Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      "req-dead-456",
	}
	_, err := upSess.CallTool(ctx, req)
	if err == nil {
		t.Fatalf("expected error calling dead process, got nil")
	}
	if err != ErrSubprocessTerminated {
		t.Logf("expected ErrSubprocessTerminated, got: %v", err)
	}

	notifErr := upSess.SendNotification([]byte(`{"jsonrpc":"2.0","method":"notify"}`))
	if notifErr != ErrSubprocessTerminated {
		t.Errorf("expected ErrSubprocessTerminated on SendNotification, got: %v", notifErr)
	}
}

func TestStdioDialer_SubprocessCrash_MultipleConcurrentCallsFailFast(t *testing.T) {
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:      "proto-multi-failfast",
		Name:    "multi-crash-target",
		Type:    "stdio",
		Command: "cat",
	}

	dialer := NewStdioDialer()
	eventCh := make(chan SSEEvent, 100)

	upSess := dialer.Dial(parentCtx, proto, eventCh, "client-multi-crash", nil)
	if upSess == nil {
		t.Fatalf("failed to dial stdio protocol")
	}
	defer upSess.Close()

	if upSess.GetStatus() != "READY" {
		t.Fatalf("expected READY status, got %s", upSess.GetStatus())
	}

	pid := upSess.cmd.Process.Pid
	if pid <= 0 {
		t.Fatalf("invalid subprocess pid: %d", pid)
	}

	const concurrentCalls = 20
	errCh := make(chan error, concurrentCalls)
	var startWg sync.WaitGroup

	// Each call uses a long 30-second timeout context. None should wait for 30s.
	for i := 0; i < concurrentCalls; i++ {
		startWg.Add(1)
		go func(callID int) {
			ctx, callCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer callCancel()

			req := &mcp.Request{
				JSONRPC: "2.0",
				Method:  "tools/call",
				ID:      fmt.Sprintf("multi-call-%d", callID),
			}
			startWg.Done()
			_, err := upSess.CallTool(ctx, req)
			errCh <- err
		}(i)
	}

	startWg.Wait()
	// Allow all calls to register in pendingCalls
	time.Sleep(25 * time.Millisecond)

	killStart := time.Now()
	_ = syscall.Kill(pid, syscall.SIGKILL)

	// All 20 calls must unblock within < 50ms (well before 30s timeout)
	timeout := time.After(200 * time.Millisecond)
	for i := 0; i < concurrentCalls; i++ {
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatalf("call %d returned nil error on subprocess crash", i)
			}
			if !errors.Is(err, ErrSubprocessTerminated) && err.Error() != ErrSubprocessTerminated.Error() {
				t.Errorf("call %d expected ErrSubprocessTerminated, got: %v", i, err)
			}
		case <-timeout:
			t.Fatalf("caller goroutine timed out waiting for fail-fast unblock after subprocess crash")
		}
	}

	killDuration := time.Since(killStart)
	t.Logf("All %d concurrent in-flight calls unblocked in %v on subprocess SIGKILL", concurrentCalls, killDuration)

	// Verify post-crash invocations fail fast at entry without attempting writes
	entryCtx, entryCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer entryCancel()

	for i := 0; i < 5; i++ {
		entryStart := time.Now()
		_, err := upSess.CallTool(entryCtx, &mcp.Request{
			JSONRPC: "2.0",
			Method:  "tools/call",
			ID:      fmt.Sprintf("post-dead-%d", i),
		})
		entryElapsed := time.Since(entryStart)
		if !errors.Is(err, ErrSubprocessTerminated) {
			t.Fatalf("expected ErrSubprocessTerminated on dead process call, got %v", err)
		}
		if entryElapsed > 5*time.Millisecond {
			t.Errorf("dead process fail-fast took %v (> 5ms)", entryElapsed)
		}
	}
}

func TestStdioDialer_SubprocessSecretHygiene_LiveProcess(t *testing.T) {
	// Set parent secrets in Gateway process
	canaryAPIKey := "canary-api-key-live-999"
	canaryAdminKey := "canary-admin-key-live-888"
	canaryHMAC := "canary-hmac-secret-live-777"
	canaryAWS := "canary-aws-secret-live-666"

	t.Setenv("API_KEY", canaryAPIKey)
	t.Setenv("ADMIN_API_KEY", canaryAdminKey)
	t.Setenv("FARADAI_WIRE_HMAC_SECRET", canaryHMAC)
	t.Setenv("AWS_SECRET_ACCESS_KEY", canaryAWS)

	dialer := NewStdioDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Child process prints its actual runtime environment formatted as a JSON-RPC notification
	proto := agent.ProtocolConfig{
		ID:      "test-secret-hygiene",
		Name:    "secret-hygiene-tool",
		Type:    "stdio",
		Command: "sh",
		Args: []string{
			"-c",
			`echo "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/env_dump\",\"params\":{\"env\":\"$(env | tr '\n' ';')\"}}"`,
		},
		Env: []string{"TOOL_CONFIG_PARAM=active_setting_123"},
	}

	eventCh := make(chan SSEEvent, 10)
	upSess := dialer.Dial(ctx, proto, eventCh, "client-hygiene-test", nil)
	if upSess == nil {
		t.Fatalf("failed to dial stdio protocol")
	}
	defer upSess.Close()

	// 1. Verify upSess.cmd.Env at the Go exec.Cmd level
	if upSess.cmd == nil || upSess.cmd.Env == nil {
		t.Fatalf("expected non-nil upSess.cmd and upSess.cmd.Env")
	}
	for _, envEntry := range upSess.cmd.Env {
		if strings.Contains(envEntry, canaryAPIKey) ||
			strings.Contains(envEntry, canaryAdminKey) ||
			strings.Contains(envEntry, canaryHMAC) ||
			strings.Contains(envEntry, canaryAWS) {
			t.Fatalf("cmd.Env contains leaked secret canary: %s", envEntry)
		}
	}

	// 2. Verify actual child process execution environment from the dumped stdout
	select {
	case ev := <-eventCh:
		if ev.Event != "message" {
			t.Fatalf("expected 'message' SSEEvent, got %s", ev.Event)
		}

		dump := ev.Data
		// Verify parent secrets are provably absent from child process
		if strings.Contains(dump, canaryAPIKey) {
			t.Errorf("CRITICAL LEAK: child process inherited parent API_KEY")
		}
		if strings.Contains(dump, canaryAdminKey) {
			t.Errorf("CRITICAL LEAK: child process inherited parent ADMIN_API_KEY")
		}
		if strings.Contains(dump, canaryHMAC) {
			t.Errorf("CRITICAL LEAK: child process inherited parent FARADAI_WIRE_HMAC_SECRET")
		}
		if strings.Contains(dump, canaryAWS) {
			t.Errorf("CRITICAL LEAK: child process inherited parent AWS_SECRET_ACCESS_KEY")
		}

		// Verify allowed protocol-specified env var is present
		if !strings.Contains(dump, "TOOL_CONFIG_PARAM=active_setting_123") {
			t.Errorf("expected child process to contain TOOL_CONFIG_PARAM=active_setting_123, but got dump: %s", dump)
		}

		// Verify safe baseline fundamentals are present
		if !strings.Contains(dump, "PATH=") {
			t.Errorf("expected child process to contain PATH= in dump: %s", dump)
		}

	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for child process env dump notification")
	}
}

func TestStdioDialer_SubprocessSecretHygiene_EmptyProtoEnv_NoFallbackToHost(t *testing.T) {
	canarySecret := "canary-secret-empty-proto-env"
	t.Setenv("API_KEY", canarySecret)

	dialer := NewStdioDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proto := agent.ProtocolConfig{
		ID:      "test-secret-hygiene-empty-env",
		Name:    "secret-hygiene-tool-empty",
		Type:    "stdio",
		Command: "sh",
		Args: []string{
			"-c",
			`echo "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/env_dump\",\"params\":{\"env\":\"$(env | tr '\n' ';')\"}}"`,
		},
		Env: nil, // Intentionally nil
	}

	eventCh := make(chan SSEEvent, 10)
	upSess := dialer.Dial(ctx, proto, eventCh, "client-hygiene-empty-test", nil)
	if upSess == nil {
		t.Fatalf("failed to dial stdio protocol")
	}
	defer upSess.Close()

	if upSess.cmd == nil || upSess.cmd.Env == nil {
		t.Fatalf("expected cmd.Env to be non-nil even when proto.Env is nil to prevent os.Environ() fallback")
	}

	select {
	case ev := <-eventCh:
		dump := ev.Data
		if strings.Contains(dump, canarySecret) {
			t.Fatalf("CRITICAL LEAK: child process inherited parent API_KEY when proto.Env is nil")
		}
		if !strings.Contains(dump, "PATH=") {
			t.Fatalf("expected PATH= in child env dump")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for child process env dump notification")
	}
}
