//go:build !windows

package session

import (
	"os/exec"
	"syscall"
	"time"
)

// setProcessGroup configures the command to run in its own independent process group.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// setCommandCancel configures cmd.Cancel to send SIGTERM to the process group when context is canceled.
func setCommandCancel(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		}
		return nil
	}
}

const defaultGracePeriod = 300 * time.Millisecond

// killProcessGroup signals the entire process group with SIGTERM, escalating to SIGKILL if ungraceful.
func killProcessGroup(cmd *exec.Cmd, procExitCh <-chan struct{}) {
	killProcessGroupWithGrace(cmd, procExitCh, defaultGracePeriod)
}

// killProcessGroupWithGrace signals the process group with SIGTERM, awaiting deterministic exit on procExitCh
// before escalating to SIGKILL upon expiration of gracePeriod.
func killProcessGroupWithGrace(cmd *exec.Cmd, procExitCh <-chan struct{}, gracePeriod time.Duration) {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return
	}
	pgid := cmd.Process.Pid

	// Attempt graceful SIGTERM to process group (-pgid)
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	if procExitCh != nil {
		select {
		case <-procExitCh:
			// Process exited gracefully and was reaped by cmd.Wait()
			return
		case <-time.After(gracePeriod):
			// Process failed to exit within grace window: escalate to SIGKILL
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			select {
			case <-procExitCh:
			case <-time.After(100 * time.Millisecond):
			}
			return
		}
	}

	// Fallback if procExitCh was not provided:
	deadline := time.Now().Add(gracePeriod)
	for time.Now().Before(deadline) {
		if (cmd.ProcessState != nil && cmd.ProcessState.Exited()) || syscall.Kill(-pgid, 0) != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
