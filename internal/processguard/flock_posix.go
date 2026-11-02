//go:build !windows

package processguard

import (
	"errors"
	"syscall"
)

func acquireOSLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
}

func releaseOSLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_UN)
}

func isLockConflict(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
