//go:build !windows

package main

import (
	"os/exec"
	"testing"
)

func TestConfigureDetachedDaemon_POSIX(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("faradaiwire", "run")
	configureDetachedDaemon(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Fatalf("expected SysProcAttr.Setsid=true on POSIX, got %+v", cmd.SysProcAttr)
	}
}
