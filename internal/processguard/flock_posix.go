//go:build !windows

package processguard

import (
	"errors"
	"os"
	"syscall"
)

func acquireOSLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
}

func releaseOSLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_UN)
}

func releaseLockFile(file *os.File, lockPath string) error {
	var errs []error
	// Remove file before releasing OS lock to avoid race conditions with next acquire.
	if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if file != nil {
		if err := releaseOSLock(file.Fd()); err != nil {
			errs = append(errs, err)
		}
		if err := file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isLockConflict(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
