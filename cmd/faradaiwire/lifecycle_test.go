package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func getDistinctLifecyclePorts(t *testing.T) (int, int) {
	t.Helper()

	allocPort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate free TCP port: %v", err)
		}
		defer ln.Close()
		addr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("unexpected listener address type %T", ln.Addr())
		}
		return addr.Port
	}

	p1 := allocPort()
	p2 := allocPort()
	for p2 == p1 {
		p2 = allocPort()
	}
	return p1, p2
}

func writeLifecycleTestConfig(t *testing.T, tempHome string, withAuditAndDB bool) (cfgPath, auditPath, dbPath string) {
	t.Helper()

	cfgPath = filepath.Join(tempHome, "config.yaml")
	listenPort, adminPort := getDistinctLifecyclePorts(t)

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenPort:  listenPort,
		AdminPort:   adminPort,
		Mode:        "stdio",
		Stdio: config.StdioConfig{
			Command:     "sleep",
			Args:        []string{"60"},
			AutoRestart: false,
		},
		ConfigPath: cfgPath,
	}

	if withAuditAndDB {
		auditPath = filepath.Join(tempHome, "audit.jsonl")
		dbPath = filepath.Join(tempHome, "wire.duckdb")
		cfg.AuditLog = config.AuditLogConfig{
			Enabled: true,
			Path:    auditPath,
		}
		cfg.Telemetry = config.TelemetryConfig{
			DBPath: dbPath,
		}
	}

	provider := config.NewYAMLConfigProvider(cfgPath)
	if err := provider.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}
	return cfgPath, auditPath, dbPath
}

func maybeExecGatewaySubprocess() {
	if os.Getenv("TEST_RUN_GATEWAY_MAIN") == "1" {
		// Reset os.Args so main() parses subcommands cleanly.
		os.Args = []string{"faradaiwire", "run", "--config", os.Getenv("TEST_CONFIG_PATH")}
		main()
		os.Exit(0)
	}
}

func startProcessOutputCapture(t *testing.T, cmd *exec.Cmd, readySubstring string) (waitProcess func() (string, error), readyCh <-chan struct{}) {
	t.Helper()

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create output pipe: %v", err)
	}

	cmd.Stdout = pipeW
	cmd.Stderr = pipeW
	cmd.WaitDelay = 3 * time.Second

	if err := cmd.Start(); err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		t.Fatalf("failed to start subprocess: %v", err)
	}
	// Close parent write-end immediately so pipeR reaches EOF when child and its process group exit.
	_ = pipeW.Close()

	var (
		mu        sync.Mutex
		output    strings.Builder
		isReady   = readySubstring == ""
		readyOnce sync.Once
		ready     = make(chan struct{})
		readDone  = make(chan struct{})
	)
	if isReady {
		readyOnce.Do(func() { close(ready) })
	}

	go func() {
		defer func() {
			readyOnce.Do(func() { close(ready) })
			close(readDone)
		}()
		buf := make([]byte, 4096)
		for {
			n, readErr := pipeR.Read(buf)
			if n > 0 {
				mu.Lock()
				output.Write(buf[:n])
				matched := false
				if !isReady && strings.Contains(output.String(), readySubstring) {
					isReady = true
					matched = true
				}
				mu.Unlock()
				if matched {
					readyOnce.Do(func() { close(ready) })
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	var (
		waitOnce sync.Once
		waitErr  error
		finalOut string
		waited   atomic.Bool
	)

	waitFn := func() (string, error) {
		waitOnce.Do(func() {
			waitErr = cmd.Wait()
			waited.Store(true)
			// Allow buffered pipe bytes to drain cleanly on EOF; if an orphaned grandchild
			// holds pipeW after an abnormal kill, close pipeR after 500ms to unblock reader.
			drainTimer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-readDone:
			case <-drainTimer.C:
			}
			drainTimer.Stop()
			_ = pipeR.Close()
			<-readDone
			mu.Lock()
			finalOut = output.String()
			mu.Unlock()
		})
		return finalOut, waitErr
	}

	t.Cleanup(func() {
		if !waited.Load() && cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGKILL)
		}
		_, _ = waitFn()
	})

	return waitFn, ready
}

func runSignalSupervisionTest(t *testing.T, testName string, sig syscall.Signal, withAuditAndDB bool) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals SIGTERM/SIGINT not supported by os.Process.Signal on Windows")
	}

	tempHome := t.TempDir()
	cfgPath, auditPath, dbPath := writeLifecycleTestConfig(t, tempHome, withAuditAndDB)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
		"API_KEY=test-key",
	)

	waitProcess, readyCh := startProcessOutputCapture(t, cmd, "Started local stdio MCP subprocess")

	select {
	case <-readyCh:
	case <-ctx.Done():
		outStr, _ := waitProcess()
		t.Fatalf("timed out waiting for gateway subprocess to become ready, output:\n%s", outStr)
	}

	if err := cmd.Process.Signal(sig); err != nil {
		outStr, _ := waitProcess()
		t.Fatalf("failed to send %s to process: %v, output:\n%s", sig, err, outStr)
	}

	outStr, waitErr := waitProcess()
	if waitErr != nil {
		t.Fatalf("process exited with error: %v, output:\n%s", waitErr, outStr)
	}

	if !strings.Contains(outStr, "Termination signal received, initiating graceful shutdown") {
		t.Errorf("expected termination signal log in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "FaradAiWire stopped cleanly.") {
		t.Errorf("expected clean stop message in output, got:\n%s", outStr)
	}

	if withAuditAndDB {
		if _, err := os.Stat(auditPath); err != nil {
			t.Errorf("expected audit log file to exist at %s: %v", auditPath, err)
		}
		if _, err := os.Stat(dbPath); err != nil {
			t.Errorf("expected telemetry db to exist at %s: %v", dbPath, err)
		}
	}
}

func TestLifecycle_SignalSupervision(t *testing.T) {
	maybeExecGatewaySubprocess()
	runSignalSupervisionTest(t, "TestLifecycle_SignalSupervision", syscall.SIGTERM, true)
}

func TestLifecycle_SignalSupervision_SIGINT(t *testing.T) {
	maybeExecGatewaySubprocess()
	runSignalSupervisionTest(t, "TestLifecycle_SignalSupervision_SIGINT", syscall.SIGINT, false)
}

func TestLifecycle_ProcessGuard_CollisionDetection(t *testing.T) {
	maybeExecGatewaySubprocess()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals SIGTERM/SIGINT not supported by os.Process.Signal on Windows")
	}

	tempHome := t.TempDir()
	cfgPath, _, _ := writeLifecycleTestConfig(t, tempHome, true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Start Process 1
	cmd1 := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_ProcessGuard_CollisionDetection$")
	cmd1.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
	)

	waitProc1, readyCh1 := startProcessOutputCapture(t, cmd1, "Started local stdio MCP subprocess")

	// Wait for Process 1 to finish booting and holding the lock
	select {
	case <-readyCh1:
	case <-ctx.Done():
		out1Str, _ := waitProc1()
		t.Fatalf("timed out waiting for process 1 to become ready, output:\n%s", out1Str)
	}

	lockPath := filepath.Join(tempHome, ".faradaiwire.lock")
	if _, err := os.Stat(lockPath); err != nil {
		out1Str, _ := waitProc1()
		t.Fatalf("process 1 failed to create lock file: %v, output:\n%s", err, out1Str)
	}

	// 2. Start Process 2 targeting the EXACT same config file
	cmd2 := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_ProcessGuard_CollisionDetection$")
	cmd2.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
	)

	out2Bytes, err2 := cmd2.CombinedOutput()
	out2Str := string(out2Bytes)

	// Process 2 must fail fast with exit code 1
	if err2 == nil {
		t.Fatalf("expected process 2 to exit with error, but it succeeded! Output:\n%s", out2Str)
	}

	var exitErr *exec.ExitError
	if errors.As(err2, &exitErr) {
		if exitErr.ExitCode() != 1 {
			t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("expected exec.ExitError, got %v", err2)
	}

	if !strings.Contains(out2Str, "FaradAiWire is already running in this directory") {
		t.Errorf("expected collision message in output, got:\n%s", out2Str)
	}

	// 3. Cleanly shut down Process 1
	if err := cmd1.Process.Signal(syscall.SIGTERM); err != nil {
		out1Str, _ := waitProc1()
		t.Fatalf("failed to send SIGTERM to process 1: %v, output:\n%s", err, out1Str)
	}
	out1Str, waitErr := waitProc1()
	if waitErr != nil {
		t.Fatalf("process 1 exited with error: %v, output:\n%s", waitErr, out1Str)
	}

	// 4. Verify that .faradaiwire.lock was cleaned up
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("expected lock file to be removed after process 1 shutdown")
	}
}

func TestLifecycle_EarlySignalDuringBootAndCleanRestart(t *testing.T) {
	maybeExecGatewaySubprocess()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals SIGTERM/SIGINT not supported by os.Process.Signal on Windows")
	}

	tempHome := t.TempDir()
	cfgPath, _, _ := writeLifecycleTestConfig(t, tempHome, true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Phase 1: Send SIGTERM immediately upon initial startup log (during NewServer / DuckDB bootstrap)
	cmd1 := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_EarlySignalDuringBootAndCleanRestart$")
	cmd1.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
	)

	waitProc1, earlyReadyCh := startProcessOutputCapture(t, cmd1, "Starting FaradAiWire")
	select {
	case <-earlyReadyCh:
	case <-ctx.Done():
		out1Str, _ := waitProc1()
		t.Fatalf("timed out waiting for process 1 initial startup log, output:\n%s", out1Str)
	}

	if err := cmd1.Process.Signal(syscall.SIGTERM); err != nil {
		out1Str, _ := waitProc1()
		t.Fatalf("failed to send early SIGTERM to process 1: %v, output:\n%s", err, out1Str)
	}

	out1Str, waitErr1 := waitProc1()
	if waitErr1 != nil {
		t.Fatalf("process 1 failed to shut down cleanly on early SIGTERM: %v, output:\n%s", waitErr1, out1Str)
	}
	if !strings.Contains(out1Str, "FaradAiWire stopped cleanly.") {
		t.Errorf("expected clean stop message in process 1 output, got:\n%s", out1Str)
	}

	lockPath := filepath.Join(tempHome, ".faradaiwire.lock")
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected lock file to be cleaned up after early SIGTERM shutdown, stat err: %v", err)
	}

	// Phase 2: Immediately restart against the same directory and DuckDB path to verify zero lock/WAL corruption
	cmd2 := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_EarlySignalDuringBootAndCleanRestart$")
	cmd2.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
	)

	waitProc2, fullReadyCh := startProcessOutputCapture(t, cmd2, "Started local stdio MCP subprocess")
	select {
	case <-fullReadyCh:
	case <-ctx.Done():
		out2Str, _ := waitProc2()
		t.Fatalf("timed out waiting for restarted process 2 to become ready, output:\n%s", out2Str)
	}

	if err := cmd2.Process.Signal(syscall.SIGTERM); err != nil {
		out2Str, _ := waitProc2()
		t.Fatalf("failed to send SIGTERM to restarted process 2: %v, output:\n%s", err, out2Str)
	}

	out2Str, waitErr2 := waitProc2()
	if waitErr2 != nil {
		t.Fatalf("restarted process 2 exited with error: %v, output:\n%s", waitErr2, out2Str)
	}
	if !strings.Contains(out2Str, "FaradAiWire stopped cleanly.") {
		t.Errorf("expected clean stop message in restarted process 2 output, got:\n%s", out2Str)
	}
}
