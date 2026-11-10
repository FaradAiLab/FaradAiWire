package console

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
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

func TestReadLineFromReader_NilAndBounded(t *testing.T) {
	t.Parallel()

	if _, err := ReadLineFromReader(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil reader")
	}

	var nilFile *os.File
	if _, err := ReadLineFromReader(context.Background(), nilFile); err == nil {
		t.Fatal("expected error for typed-nil *os.File")
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadLineFromReader(canceledCtx, strings.NewReader("y\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on pre-canceled ctx, got %v", err)
	}

	longInput := strings.Repeat("a", maxLineBytes+50) + "\nyes\n"
	r := strings.NewReader(longInput)
	line1, err := ReadLineFromReader(context.Background(), r)
	if err != nil {
		t.Fatalf("unexpected error reading first bounded line: %v", err)
	}
	if len(line1) != maxLineBytes {
		t.Fatalf("expected truncated length %d, got %d", maxLineBytes, len(line1))
	}
	line2, err := ReadLineFromReader(context.Background(), r)
	if err != nil {
		t.Fatalf("expected second line after bounded read (no bufio over-read), got %v", err)
	}
	if line2 != "yes" {
		t.Fatalf("expected second line %q, got %q", "yes", line2)
	}
}

func TestNewFileConsole_CloseSameHandleOnce(t *testing.T) {
	t.Parallel()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer pw.Close()

	c := NewFileConsole(pr, pr)
	if err := c.Close(); err != nil {
		t.Fatalf("expected closing shared in/out handle once to succeed, got: %v", err)
	}
}
