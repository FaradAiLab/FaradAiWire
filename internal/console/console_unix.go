//go:build !windows

package console

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type unixConsole struct {
	in         *os.File
	out        io.WriteCloser
	closeFiles bool
}

// OpenInteractiveConsole opens the physical controlling terminal (/dev/tty) on UNIX/macOS
// so HITL prompts remain interactive even when standard I/O carries piped JSON-RPC,
// falling back to os.Stdin/os.Stdout without closing them if they are interactive TTYs.
func OpenInteractiveConsole() (InteractiveConsole, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		return NewFileConsole(tty, tty), nil
	}
	if isTerminalFile(os.Stdin) && isTerminalFile(os.Stdout) {
		return &unixConsole{in: os.Stdin, out: os.Stdout, closeFiles: false}, nil
	}
	return nil, err
}

func isTerminalFile(f *os.File) bool {
	if f == nil {
		return false
	}
	_, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	return err == nil
}

// NewFileConsole wraps an open readable file handle and output writer as an InteractiveConsole.
func NewFileConsole(in *os.File, out io.WriteCloser) InteractiveConsole {
	return &unixConsole{in: in, out: out, closeFiles: true}
}

func newNonClosingFileConsole(in *os.File) InteractiveConsole {
	return &unixConsole{in: in, closeFiles: false}
}

func (c *unixConsole) Write(p []byte) (int, error) {
	if c.out == nil {
		return len(p), nil
	}
	return c.out.Write(p)
}

func (c *unixConsole) Close() error {
	if !c.closeFiles {
		return nil
	}
	var firstErr error
	if c.in != nil {
		firstErr = c.in.Close()
	}
	if c.out != nil && c.out != any(c.in) {
		if err := c.out.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ReadLine polls the underlying file descriptor at short intervals using unix.Poll so ctx cancellation
// terminates the read without blocking Close() on non-kqueue character devices like /dev/tty.
func (c *unixConsole) ReadLine(ctx context.Context) (string, error) {
	rawConn, err := c.in.SyscallConn()
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	var buf [1]byte

	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		ready, pollErr := pollReadable(rawConn, 100)
		if pollErr != nil {
			return "", pollErr
		}
		if !ready {
			continue
		}

		n, readErr := c.in.Read(buf[:])
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			if sb.Len() < 256 {
				sb.WriteByte(buf[0])
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && sb.Len() > 0 {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			return "", readErr
		}
	}
}

func pollReadable(rawConn interface{ Control(func(fd uintptr)) error }, timeoutMs int) (bool, error) {
	var ready bool
	var pollErr error

	err := rawConn.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			n, err := unix.Poll(fds, timeoutMs)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				pollErr = err
				return
			}
			if n > 0 && (fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR)) != 0 {
				ready = true
			}
			return
		}
	})
	if err != nil {
		return false, err
	}
	return ready, pollErr
}
