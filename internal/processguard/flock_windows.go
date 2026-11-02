//go:build windows

package processguard

import (
	"errors"

	"golang.org/x/sys/windows"
)

func acquireOSLock(fd uintptr) error {
	var overlapped windows.Overlapped
	handle := windows.Handle(fd)
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	return windows.LockFileEx(handle, flags, 0, 1, 0, &overlapped)
}

func releaseOSLock(fd uintptr) error {
	var overlapped windows.Overlapped
	handle := windows.Handle(fd)
	return windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
}

func isLockConflict(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
