//go:build windows

package console

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"

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
	if c.out != nil {
		if err := c.out.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ReadLine awaits a single line from CONIN$ and aborts pending synchronous I/O via CancelIoEx
// when ctx is canceled so the reader goroutine always exits cleanly.
func (c *windowsConsole) ReadLine(ctx context.Context) (string, error) {
	type readResult struct {
		line string
		err  error
	}

	resCh := make(chan readResult, 1)
	go func() {
		reader := bufio.NewReader(c.in)
		text, err := reader.ReadString('\n')
		resCh <- readResult{
			line: strings.TrimRight(text, "\r\n"),
			err:  err,
		}
	}()

	select {
	case res := <-resCh:
		return res.line, res.err
	case <-ctx.Done():
		_ = windows.CancelIoEx(windows.Handle(c.in.Fd()), nil)
		<-resCh
		return "", ctx.Err()
	}
}
