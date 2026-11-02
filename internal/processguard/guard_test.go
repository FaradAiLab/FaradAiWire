package processguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessGuard_AcquireAndRelease(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, ".faradaiwire.lock")

	guard := New(lockPath)
	if err := guard.Acquire(); err != nil {
		t.Fatalf("expected acquire to succeed, got: %v", err)
	}

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
