//go:build windows

package console

import (
	"context"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

type windowsConsole struct {
	in         *os.File
	out        io.WriteCloser
	closeFiles bool
}

// OpenInteractiveConsole opens Windows console input/output handles (CONIN$ and CONOUT$)
// so HITL prompts remain interactive even when standard I/O carries piped JSON-RPC,
// falling back to os.Stdin/os.Stdout without closing them if they are interactive console handles.
func OpenInteractiveConsole() (InteractiveConsole, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err == nil {
		out, outErr := os.OpenFile("CONOUT$", os.O_RDWR, 0)
		if outErr == nil {
			return NewFileConsole(in, out), nil
		}
		_ = in.Close()
		err = outErr
	}
	if isConsoleFile(os.Stdin) && isConsoleFile(os.Stdout) {
		return &windowsConsole{in: os.Stdin, out: os.Stdout, closeFiles: false}, nil
	}
	return nil, err
}

func isConsoleFile(f *os.File) bool {
	if f == nil {
		return false
	}
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// NewFileConsole wraps an open readable file handle and output writer as an InteractiveConsole.
func NewFileConsole(in *os.File, out io.WriteCloser) InteractiveConsole {
	return &windowsConsole{in: in, out: out, closeFiles: true}
}

func newNonClosingFileConsole(in *os.File) InteractiveConsole {
	return &windowsConsole{in: in, closeFiles: false}
}

func (c *windowsConsole) Write(p []byte) (int, error) {
	if c.out == nil {
		return len(p), nil
	}
	return c.out.Write(p)
}

func (c *windowsConsole) Close() error {
	if !c.closeFiles {
		if c.in != nil {
			_ = windows.CancelIoEx(windows.Handle(c.in.Fd()), nil)
		}
		return nil
	}
	var firstErr error
	if c.in != nil {
		_ = windows.CancelIoEx(windows.Handle(c.in.Fd()), nil)
		firstErr = c.in.Close()
	}
	if c.out != nil && c.out != any(c.in) {
		if err := c.out.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ReadLine awaits a single line from CONIN$ and aborts pending synchronous I/O via CancelIoEx
// when ctx is canceled so the reader goroutine always exits cleanly.
func (c *windowsConsole) ReadLine(ctx context.Context) (string, error) {
	if c == nil || c.in == nil {
		return "", os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	type readResult struct {
		line string
		err  error
	}

	handle := windows.Handle(c.in.Fd())
	resCh := make(chan readResult, 1)
	go func() {
		line, err := readBoundedLine(c.in)
		resCh <- readResult{
			line: line,
			err:  err,
		}
	}()

	select {
	case res := <-resCh:
		return res.line, res.err
	case <-ctx.Done():
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			_ = windows.CancelIoEx(handle, nil)
			select {
			case <-resCh:
				return "", ctx.Err()
			case <-ticker.C:
			}
		}
	}
}
