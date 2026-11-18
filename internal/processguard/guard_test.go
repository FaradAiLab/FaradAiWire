package processguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestProcessGuard_AcquireAndRelease(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")

	guard := New(lockPath)
	if err := guard.Acquire(); err != nil {
		t.Fatalf("expected acquire to succeed, got: %v", err)
	}
	defer func() { _ = guard.Release() }()

	if guard.PID() != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), guard.PID())
	}

	// Verify file exists and contains PID
	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read lock file: %v", err)
	}
	if len(content) == 0 {
		t.Errorf("expected non-empty lock file")
	}

	// Release
	if err := guard.Release(); err != nil {
		t.Fatalf("expected release to succeed, got: %v", err)
	}

	// Lock file should be removed
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("expected lock file to be removed after release")
	}
}

func TestProcessGuard_CollisionDetection(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "data", ".faradaiwire.lock")

	guard1 := New(lockPath)
	if err := guard1.Acquire(); err != nil {
		t.Fatalf("guard1 acquire failed: %v", err)
	}
	defer guard1.Release()

	// Second guard attempting to acquire the same lock file must fail
	guard2 := New(lockPath)
	err := guard2.Acquire()
	if err == nil {
		t.Fatalf("expected guard2 acquire to fail with collision error, but got nil")
	}

	var alreadyRunningErr *ErrAlreadyRunning
	if !errors.As(err, &alreadyRunningErr) {
		t.Fatalf("expected ErrAlreadyRunning, got: %T (%v)", err, err)
	}

	if alreadyRunningErr.PID != os.Getpid() {
		t.Errorf("expected conflicting PID %d, got %d", os.Getpid(), alreadyRunningErr.PID)
	}
}

func TestProcessGuard_ReleaseIdempotency(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")

	guard := New(lockPath)
	if err := guard.Acquire(); err != nil {
		t.Fatalf("acquire failed: %v", err)
	}

	// Multiple releases should succeed cleanly without error
	if err := guard.Release(); err != nil {
		t.Errorf("first release failed: %v", err)
	}
	if err := guard.Release(); err != nil {
		t.Errorf("second release failed: %v", err)
	}
}

func TestProcessGuard_ReacquireAfterRelease(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")

	guard1 := New(lockPath)
	if err := guard1.Acquire(); err != nil {
		t.Fatalf("guard1 acquire failed: %v", err)
	}
	if err := guard1.Release(); err != nil {
		t.Fatalf("guard1 release failed: %v", err)
	}

	// Another guard can now acquire the lock immediately
	guard2 := New(lockPath)
	if err := guard2.Acquire(); err != nil {
		t.Fatalf("guard2 acquire failed after guard1 released: %v", err)
	}
	defer guard2.Release()
}

func TestProcessGuard_BypassEnvVar(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")

	t.Setenv(EnvDisableProcessLock, "true")

	guard1 := New(lockPath)
	if err := guard1.Acquire(); err != nil {
		t.Fatalf("guard1 acquire with bypass failed: %v", err)
	}
	defer guard1.Release()

	// With bypass enabled, guard2 also succeeds
	guard2 := New(lockPath)
	if err := guard2.Acquire(); err != nil {
		t.Fatalf("guard2 acquire with bypass failed: %v", err)
	}
	defer guard2.Release()
}

func TestProcessGuard_StaleLockFileTruncated(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")

	// Simulate an unlocked stale lock file left behind by a crashed process with a longer PID string.
	if err := os.WriteFile(lockPath, []byte("999999999999\n"), 0600); err != nil {
		t.Fatalf("failed to seed stale lock file: %v", err)
	}

	guard := New(lockPath)
	if err := guard.Acquire(); err != nil {
		t.Fatalf("expected acquire on stale lock file to succeed, got: %v", err)
	}
	defer func() { _ = guard.Release() }()

	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("failed to read lock file: %v", err)
	}
	expected := fmt.Sprintf("%d", os.Getpid())
	if got := strings.TrimSpace(string(content)); got != expected {
		t.Errorf("expected lock file PID %q, got %q", expected, got)
	}
}

func TestProcessGuard_ConcurrentAcquireRelease(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")
	guard := New(lockPath)
	defer func() { _ = guard.Release() }()

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := guard.Acquire(); err != nil {
				errs <- err
				return
			}
			_ = guard.PID()
			if err := guard.Release(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("unexpected concurrent Acquire/Release error: %v", err)
	}
}
