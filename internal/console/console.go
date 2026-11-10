package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxLineBytes = 256

// InteractiveConsole provides cross-platform terminal I/O supporting context-aware cancellation
// so blocking interactive reads terminate cleanly when resolved externally or timed out.
type InteractiveConsole interface {
	io.Writer
	// ReadLine reads a single newline-terminated line or returns ctx.Err() if canceled first.
	ReadLine(ctx context.Context) (string, error)
	// Close releases underlying terminal device handles.
	Close() error
}

// ReadLineFromReader reads a single newline-terminated line from r while respecting ctx cancellation.
// When r is an *os.File (such as an os.Pipe or terminal descriptor), it uses the non-leaking
// OS-native poll/CancelIoEx console reader without closing the caller's file descriptor.
func ReadLineFromReader(ctx context.Context, r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("nil console reader")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if f, ok := r.(*os.File); ok {
		if f == nil {
			return "", os.ErrInvalid
		}
		c := newNonClosingFileConsole(f)
		return c.ReadLine(ctx)
	}

	type readResult struct {
		line string
		err  error
	}
	resCh := make(chan readResult, 1)
	go func() {
		line, err := readBoundedLine(r)
		resCh <- readResult{line: line, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-resCh:
		return res.line, res.err
	}
}

func readBoundedLine(r io.Reader) (string, error) {
	var sb strings.Builder
	var buf [1]byte
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			if sb.Len() < maxLineBytes {
				sb.WriteByte(buf[0])
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && sb.Len() > 0 {
				return strings.TrimRight(sb.String(), "\r"), nil
			}
			return "", err
		}
	}
}

// ParseYesNoAnswer evaluates standard interactive confirmation responses ("y" or "yes").
func ParseYesNoAnswer(answer string) bool {
	lower := strings.ToLower(strings.TrimSpace(answer))
	return lower == "y" || lower == "yes"
}

// SanitizeTerminalText neutralizes ANSI/VT100 escape sequences and ASCII/C1 control characters
// (CWE-150) before rendering untrusted tool names or arguments to an operator's terminal.
func SanitizeTerminalText(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			sb.WriteByte(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			_, _ = fmt.Fprintf(&sb, "\\x%02x", r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
