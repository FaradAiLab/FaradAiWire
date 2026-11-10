//go:build !windows

package console

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type rawFDConn uintptr

func (f rawFDConn) Control(fn func(uintptr)) error {
	fn(uintptr(f))
	return nil
}

func TestIsTerminalFile_NonMutating(t *testing.T) {
	t.Parallel()

	if isTerminalFile(nil) {
		t.Fatal("expected isTerminalFile(nil) to be false")
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	if isTerminalFile(pr) {
		t.Fatal("expected pipe reader not to be reported as a terminal")
	}
}

func TestPollReadable_ClosedFD_POLLNVAL(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("unix.Pipe failed: %v", err)
	}
	_ = unix.Close(fds[0])
	_ = unix.Close(fds[1])

	ready, err := pollReadable(rawFDConn(uintptr(fds[0])), 10)
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("expected closed fd error on POLLNVAL, got ready=%v err=%v", ready, err)
	}
}
