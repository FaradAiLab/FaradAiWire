//go:build windows

package processguard

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// windowsLockOffset places the mandatory 1-byte LockFileEx range well past the
// PID payload stored at offset 0 so other processes can read the conflicting PID
// while the exclusive lock is held.
const windowsLockOffset uint32 = 0x40000000

func acquireOSLock(fd uintptr) error {
	overlapped := windows.Overlapped{
		Offset: windowsLockOffset,
	}
	handle := windows.Handle(fd)
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	return windows.LockFileEx(handle, flags, 0, 1, 0, &overlapped)
}

func releaseOSLock(fd uintptr) error {
	overlapped := windows.Overlapped{
		Offset: windowsLockOffset,
	}
	handle := windows.Handle(fd)
	return windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
}

func releaseLockFile(file *os.File, lockPath string) error {
	var errs []error
	// Windows cannot remove an open file handle without leaving a delete-pending entry,
	// so unlock and close the handle before unlinking the lock file.
	if file != nil {
		if err := releaseOSLock(file.Fd()); err != nil {
			errs = append(errs, err)
		}
		if err := file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func isLockConflict(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
