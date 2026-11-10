//go:build windows

package admin

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type probeProcessGuard struct {
	afterStart func()
	killTree   func()
	markReaped func()
}

func configureProbeProcess(cmd *exec.Cmd) probeProcessGuard {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}

	var mu sync.Mutex
	var job windows.Handle
	var closed bool
	var reaped bool

	afterStart := func() {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return
		}
		j, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(
			j,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		); err != nil {
			_ = windows.CloseHandle(j)
			return
		}
		procHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
		if err != nil {
			_ = windows.CloseHandle(j)
			return
		}
		defer windows.CloseHandle(procHandle)
		if err := windows.AssignProcessToJobObject(j, procHandle); err != nil {
			_ = windows.CloseHandle(j)
			return
		}
		mu.Lock()
		if closed {
			_ = windows.CloseHandle(j)
		} else {
			job = j
		}
		mu.Unlock()
	}

	killTree := func() {
		mu.Lock()
		j := job
		job = 0
		closed = true
		alreadyReaped := reaped
		mu.Unlock()

		if j != 0 {
			_ = windows.TerminateJobObject(j, 1)
			_ = windows.CloseHandle(j)
		}
		if !alreadyReaped && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}

	markReaped := func() {
		mu.Lock()
		j := job
		job = 0
		closed = true
		reaped = true
		mu.Unlock()
		if j != 0 {
			_ = windows.CloseHandle(j)
		}
	}

	cmd.Cancel = func() error {
		killTree()
		return nil
	}

	return probeProcessGuard{
		afterStart: afterStart,
		killTree:   killTree,
		markReaped: markReaped,
	}
}
