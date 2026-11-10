//go:build windows

package main

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestConfigureDetachedDaemon_Windows(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("faradaiwire", "run")
	configureDetachedDaemon(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be initialized on Windows")
	}
	wantFlags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	if cmd.SysProcAttr.CreationFlags != wantFlags {
		t.Fatalf("expected CreationFlags=0x%x, got 0x%x", wantFlags, cmd.SysProcAttr.CreationFlags)
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("expected HideWindow=true on Windows detached daemon")
	}
}
