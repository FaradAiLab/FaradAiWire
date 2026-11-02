package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestLifecycle_SignalSupervision(t *testing.T) {
	if os.Getenv("TEST_RUN_GATEWAY_MAIN") == "1" {
		// Reset os.Args so main() parses subcommands cleanly
		os.Args = []string{"faradaiwire", "run", "--config", os.Getenv("TEST_CONFIG_PATH")}
		main()
		os.Exit(0)
	}

	tempHome := t.TempDir()
	cfgPath := filepath.Join(tempHome, "config.yaml")
	auditPath := filepath.Join(tempHome, "audit.jsonl")
	dbPath := filepath.Join(tempHome, "wire.duckdb")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenPort:  0,
		AdminPort:   0,
		Mode:        "stdio",
		Stdio: config.StdioConfig{
			Command:     "sleep",
			Args:        []string{"60"},
			AutoRestart: false,
		},
		AuditLog: config.AuditLogConfig{
			Enabled: true,
			Path:    auditPath,
		},
		Telemetry: config.TelemetryConfig{
			DBPath: dbPath,
		},
		ConfigPath: cfgPath,
	}

	provider := config.NewYAMLConfigProvider(cfgPath)
	if err := provider.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	// Spawn subprocess running the current test binary with TEST_RUN_GATEWAY_MAIN=1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_SignalSupervision$")
	cmd.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
		"API_KEY=test-key",
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}

	var output strings.Builder
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(io.MultiReader(stdoutPipe, stderrPipe))
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line + "\n")
		}
	}()

	// Wait for gateway to boot and log startup
	time.Sleep(400 * time.Millisecond)

	// Send SIGTERM to child process
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to process: %v", err)
	}

	// Wait for process to exit cleanly
	waitErr := cmd.Wait()
	<-readDone

	outStr := output.String()

	if waitErr != nil {
		t.Fatalf("process exited with error: %v, output:\n%s", waitErr, outStr)
	}

	// Assert shutdown log sequence
	if !strings.Contains(outStr, "Termination signal received, initiating graceful shutdown") {
		t.Errorf("expected termination signal log in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "FaradAiWire stopped cleanly.") {
		t.Errorf("expected clean stop message in output, got:\n%s", outStr)
	}

	// Verify audit log file was created and can be read
	if _, err := os.Stat(auditPath); err != nil {
		t.Errorf("expected audit log file to exist at %s: %v", auditPath, err)
	}

	// Verify DuckDB database file was created without WAL lock/corruption
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected telemetry db to exist at %s: %v", dbPath, err)
	}
}

func TestLifecycle_SignalSupervision_SIGINT(t *testing.T) {
	if os.Getenv("TEST_RUN_GATEWAY_MAIN") == "1" {
		os.Args = []string{"faradaiwire", "run", "--config", os.Getenv("TEST_CONFIG_PATH")}
		main()
		os.Exit(0)
	}

	tempHome := t.TempDir()
	cfgPath := filepath.Join(tempHome, "config.yaml")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenPort:  0,
		AdminPort:   0,
		Mode:        "stdio",
		Stdio: config.StdioConfig{
			Command:     "sleep",
			Args:        []string{"60"},
			AutoRestart: false,
		},
		ConfigPath: cfgPath,
	}

	provider := config.NewYAMLConfigProvider(cfgPath)
	if err := provider.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_SignalSupervision_SIGINT$")
	cmd.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start subprocess: %v", err)
	}

	var output strings.Builder
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(io.MultiReader(stdoutPipe, stderrPipe))
		for scanner.Scan() {
			output.WriteString(scanner.Text() + "\n")
		}
	}()

	time.Sleep(400 * time.Millisecond)

	// Send SIGINT (interrupt)
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("failed to send SIGINT to process: %v", err)
	}

	waitErr := cmd.Wait()
	<-readDone

	outStr := output.String()
	if waitErr != nil {
		t.Fatalf("process exited with error: %v, output:\n%s", waitErr, outStr)
	}

	if !strings.Contains(outStr, "Termination signal received, initiating graceful shutdown") {
		t.Errorf("expected termination signal log in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "FaradAiWire stopped cleanly.") {
		t.Errorf("expected clean stop message in output, got:\n%s", outStr)
	}
}

func TestLifecycle_ProcessGuard_CollisionDetection(t *testing.T) {
	if os.Getenv("TEST_RUN_GATEWAY_MAIN") == "1" {
		os.Args = []string{"faradaiwire", "run", "--config", os.Getenv("TEST_CONFIG_PATH")}
		main()
		os.Exit(0)
	}

	tempHome := t.TempDir()
	cfgPath := filepath.Join(tempHome, "config.yaml")
	auditPath := filepath.Join(tempHome, "audit.jsonl")
	dbPath := filepath.Join(tempHome, "wire.duckdb")

	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenPort:  0,
		AdminPort:   0,
		Mode:        "stdio",
		Stdio: config.StdioConfig{
			Command:     "sleep",
			Args:        []string{"60"},
			AutoRestart: false,
		},
		AuditLog: config.AuditLogConfig{
			Enabled: true,
			Path:    auditPath,
		},
		Telemetry: config.TelemetryConfig{
			DBPath: dbPath,
		},
		ConfigPath: cfgPath,
	}

	provider := config.NewYAMLConfigProvider(cfgPath)
	if err := provider.Save(cfg); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Start Process 1
	cmd1 := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycle_ProcessGuard_CollisionDetection$")
	cmd1.Env = append(os.Environ(),
		"TEST_RUN_GATEWAY_MAIN=1",
		"TEST_CONFIG_PATH="+cfgPath,
		"FARADAI_WIRE_HOME="+tempHome,
	)

	stdout1, err := cmd1.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	stderr1, err := cmd1.StderrPipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}

	if err := cmd1.Start(); err != nil {
		t.Fatalf("failed to start process 1: %v", err)
	}
	defer func() {
		if cmd1.Process != nil {
			_ = cmd1.Process.Signal(syscall.SIGKILL)
		}
	}()

	var out1 strings.Builder
	go func() {
		scanner := bufio.NewScanner(io.MultiReader(stdout1, stderr1))
		for scanner.Scan() {
			out1.WriteString(scanner.Text() + "\n")
		}
	}()

	// Wait up to 1 second for Process 1 to acquire the lock
	lockPath := filepath.Join(tempHome, ".faradaiwire.lock")
	lockAcquired := false
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(lockPath); err == nil {
			lockAcquired = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !lockAcquired {
		t.Fatalf("process 1 failed to create lock file within 1s. Output:\n%s", out1.String())
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
	time.Sleep(200 * time.Millisecond)
	if err := cmd1.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to process 1: %v", err)
	}
	waitErr := cmd1.Wait()
	if waitErr != nil {
		t.Logf("cmd1 output:\n%s\nwaitErr: %v", out1.String(), waitErr)
	}

	// 4. Verify that .faradaiwire.lock was cleaned up
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("expected lock file to be removed after process 1 shutdown")
	}
}

