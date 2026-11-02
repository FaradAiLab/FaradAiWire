package processguard

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// EnvDisableProcessLock defines the environment variable used to bypass process file locking (e.g. in Kubernetes/containers).
const EnvDisableProcessLock = "FARADAI_WIRE_DISABLE_PROCESS_LOCK"

// ErrAlreadyRunning indicates that another FaradAiWire daemon is currently active on the target data directory.
type ErrAlreadyRunning struct {
	PID      int
	LockPath string
}

func (e *ErrAlreadyRunning) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("FaradAiWire is already running in this directory (PID: %d). Only one instance can operate on the same data directory at a time.", e.PID)
	}
	return fmt.Sprintf("FaradAiWire is already running in this directory (lock: %s). Only one instance can operate on the same data directory at a time.", e.LockPath)
}

// Guard abstracts exclusive process instance synchronization for the gateway runtime.
type Guard interface {
	Acquire() error
	Release() error
	LockPath() string
	PID() int
}

// ProcessGuard implements Guard using OS-level non-blocking file locks.
type ProcessGuard struct {
	lockPath string
	file     *os.File
	pid      int
	isLocked bool
	bypassed bool
	mu       sync.Mutex
}

// New creates a new ProcessGuard for the specified lock file path.
func New(lockPath string) *ProcessGuard {
	return &ProcessGuard{
		lockPath: filepath.Clean(lockPath),
	}
}

// LockPath returns the configured filesystem path of the lock file.
func (p *ProcessGuard) LockPath() string {
	return p.lockPath
}

// PID returns the active process ID held by this guard.
func (p *ProcessGuard) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// Acquire attempts to gain exclusive ownership of the lock file.
// If another process holds the lock, ErrAlreadyRunning is returned containing the active process's PID.
func (p *ProcessGuard) Acquire() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isLocked {
		return nil
	}

	// Support containerized and multi-pod EE environments where locking is disabled
	if val := strings.ToLower(strings.TrimSpace(os.Getenv(EnvDisableProcessLock))); val == "true" || val == "1" {
		p.bypassed = true
		p.isLocked = true
		p.pid = os.Getpid()
		return nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(p.lockPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create lock directory '%s': %w", dir, err)
		}
	}

	f, err := os.OpenFile(p.lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file '%s': %w", p.lockPath, err)
	}

	// Attempt non-blocking exclusive OS lock
	if lockErr := acquireOSLock(f.Fd()); lockErr != nil {
		if isLockConflict(lockErr) {
			// Read conflicting PID from lock file
			data, _ := io.ReadAll(f)
			_ = f.Close()
			conflictingPID, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			return &ErrAlreadyRunning{
				PID:      conflictingPID,
				LockPath: p.lockPath,
			}
		}
		_ = f.Close()
		return fmt.Errorf("failed to acquire OS lock on '%s': %w", p.lockPath, lockErr)
	}

	// Record current PID into lock file
	if err := f.Truncate(0); err == nil {
		_, _ = f.Seek(0, io.SeekStart)
		_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
		_ = f.Sync()
	}

	p.file = f
	p.isLocked = true
	p.pid = os.Getpid()
	return nil
}

// Release yields the exclusive lock, removes the lock file, and closes the handle.
func (p *ProcessGuard) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isLocked || p.bypassed {
		p.isLocked = false
		return nil
	}

	var releaseErrs []error

	// Remove file before releasing OS lock to avoid race conditions with next acquire
	if err := os.Remove(p.lockPath); err != nil && !os.IsNotExist(err) {
		releaseErrs = append(releaseErrs, err)
	}

	if p.file != nil {
		if err := releaseOSLock(p.file.Fd()); err != nil {
			releaseErrs = append(releaseErrs, err)
		}
		if err := p.file.Close(); err != nil {
			releaseErrs = append(releaseErrs, err)
		}
		p.file = nil
	}

	p.isLocked = false
	p.pid = 0

	if len(releaseErrs) > 0 {
		return releaseErrs[0]
	}
	return nil
}
