//go:build windows

package session

import (
	"os/exec"
	"strconv"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) {}

func setCommandCancel(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			killCmd := exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
			_ = killCmd.Run()
			return cmd.Process.Kill()
		}
		return nil
	}
}

const defaultGracePeriod = 300 * time.Millisecond

func killProcessGroup(cmd *exec.Cmd, procExitCh <-chan struct{}) {
	killProcessGroupWithGrace(cmd, procExitCh, defaultGracePeriod)
}

func killProcessGroupWithGrace(cmd *exec.Cmd, procExitCh <-chan struct{}, gracePeriod time.Duration) {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return
	}
	pid := cmd.Process.Pid

	// Terminate the entire process tree using taskkill.exe /T /F /PID <pid>
	killCmd := exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(pid))
	_ = killCmd.Run()

	// Direct kill safety fallback
	_ = cmd.Process.Kill()

	if procExitCh != nil {
		select {
		case <-procExitCh:
			return
		case <-time.After(gracePeriod):
			return
		}
	}
}
