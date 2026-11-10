//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// configureDetachedDaemon isolates the spawned daemon into its own POSIX session
// so closing the IDE or stdio bridge does not send SIGHUP/SIGINT to the shared gateway.
func configureDetachedDaemon(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
