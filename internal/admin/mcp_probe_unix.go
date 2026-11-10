//go:build !windows

package admin

import (
	"os/exec"
	"sync"
	"syscall"
)

type probeProcessGuard struct {
	afterStart func()
	killTree   func()
	markReaped func()
}

func configureProbeProcess(cmd *exec.Cmd) probeProcessGuard {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var mu sync.Mutex
	var reaped bool

	killTree := func() {
		mu.Lock()
		defer mu.Unlock()
		if reaped || cmd.Process == nil || cmd.Process.Pid <= 0 {
			return
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	markReaped := func() {
		mu.Lock()
		reaped = true
		mu.Unlock()
	}

	cmd.Cancel = func() error {
		killTree()
		return nil
	}

	return probeProcessGuard{
		afterStart: func() {},
		killTree:   killTree,
		markReaped: markReaped,
	}
}
