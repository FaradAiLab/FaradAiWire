package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

type nopWriteCloser struct {
	io.Writer
}

func (n *nopWriteCloser) Close() error { return nil }

func TestParseYesNoAnswer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want bool
	}{
		{"y", true},
		{"Y\r\n", true},
		{" yes ", true},
		{"n", false},
		{"no", false},
		{"", false},
	}

	for _, tc := range cases {
		if got := ParseYesNoAnswer(tc.in); got != tc.want {
			t.Errorf("ParseYesNoAnswer(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestOpenInteractiveConsole_CancelableReadOnPipe(t *testing.T) {
	t.Parallel()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	var out bytes.Buffer
	c := NewFileConsole(pr, &nopWriteCloser{Writer: &out})

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, readErr := c.ReadLine(ctx)
	elapsed := time.Since(start)

	if !errors.Is(readErr, context.DeadlineExceeded) && !errors.Is(readErr, context.Canceled) {
		t.Fatalf("expected context cancellation error, got: %v", readErr)
	}
	if elapsed > 600*time.Millisecond {
		t.Fatalf("expected ReadLine to unblock promptly on ctx cancel, took %v", elapsed)
	}
}

func TestSanitizeTerminalText(t *testing.T) {
	t.Parallel()

	raw := "delete_record\x1b[2J\x1b[H\r\n\x07{\"id\":1}"
	got := SanitizeTerminalText(raw)
	want := "delete_record\\x1b[2J\\x1b[H  \\x07{\"id\":1}"
	if got != want {
		t.Fatalf("SanitizeTerminalText(%q) = %q, want %q", raw, got, want)
	}
}
