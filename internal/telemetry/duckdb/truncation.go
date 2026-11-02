package duckdb

import (
	"bytes"
	"fmt"
	"io"
)

// DefaultMaxPayloadBytes is the maximum raw payload size stored before truncation (64 KB).
const DefaultMaxPayloadBytes = 64 * 1024

// FormatTruncatedTrailer produces a deterministic trailer indicating the total pre-truncation payload size.
func FormatTruncatedTrailer(totalBytes int) string {
	if totalBytes >= 1024*1024 {
		return fmt.Sprintf("\n[TRUNCATED - Total Size: %.2f MB]", float64(totalBytes)/(1024*1024))
	}
	if totalBytes >= 1024 {
		return fmt.Sprintf("\n[TRUNCATED - Total Size: %.2f KB]", float64(totalBytes)/1024)
	}
	return fmt.Sprintf("\n[TRUNCATED - Total Size: %d bytes]", totalBytes)
}

// TruncatePayload takes raw payload bytes, limits them to maxBytes, and appends a deterministic trailer if truncated.
// Returns the truncated string preview and total original payload byte length.
func TruncatePayload(payload []byte, maxBytes int) (string, int) {
	totalLen := len(payload)
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPayloadBytes
	}

	if totalLen <= maxBytes {
		return string(payload), totalLen
	}

	// Read bounded slice up to maxBytes
	preview := string(payload[:maxBytes])
	trailer := FormatTruncatedTrailer(totalLen)
	return preview + trailer, totalLen
}

// TruncateReader reads up to maxBytes from an io.Reader, determining whether it exceeded maxBytes.
// If the reader contains more than maxBytes, it appends a deterministic trailer.
func TruncateReader(r io.Reader, maxBytes int) (string, int, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPayloadBytes
	}

	var buf bytes.Buffer
	lr := io.LimitReader(r, int64(maxBytes+1))
	n, err := io.Copy(&buf, lr)
	if err != nil && err != io.EOF {
		return "", 0, err
	}

	if n <= int64(maxBytes) {
		return buf.String(), int(n), nil
	}

	// Data exceeded maxBytes. Read remaining bytes from r to count total length.
	totalCount := n
	discardBuf := make([]byte, 32*1024)
	for {
		dn, dErr := r.Read(discardBuf)
		totalCount += int64(dn)
		if dErr != nil {
			break
		}
	}

	// Discard the 1 extra byte we read beyond maxBytes
	previewBytes := buf.Bytes()[:maxBytes]
	trailer := FormatTruncatedTrailer(int(totalCount))
	return string(previewBytes) + trailer, int(totalCount), nil
}

// TruncateString truncates a string payload exceeding maxBytes.
func TruncateString(s string, maxBytes int) (string, int) {
	return TruncatePayload([]byte(s), maxBytes)
}
