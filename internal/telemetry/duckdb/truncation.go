package duckdb

import (
	"bytes"
	"io"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

// DefaultMaxPayloadBytes is the maximum raw payload size stored before truncation (64 KB).
const DefaultMaxPayloadBytes = 64 * 1024

// FormatTruncatedTrailer produces a deterministic trailer indicating the total pre-truncation payload size.
func FormatTruncatedTrailer(totalBytes int) string {
	return filter.FormatTruncatedTrailer(totalBytes)
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

	return string(payload[:maxBytes]) + FormatTruncatedTrailer(totalLen), totalLen
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

	// Data exceeded maxBytes. Drain remaining bytes with io.Discard to avoid per-call buffer allocations.
	discarded, _ := io.Copy(io.Discard, r)
	totalCount := n + discarded

	// Discard the 1 extra byte we read beyond maxBytes
	previewBytes := buf.Bytes()[:maxBytes]
	return string(previewBytes) + FormatTruncatedTrailer(int(totalCount)), int(totalCount), nil
}

// TruncateString truncates a string payload exceeding maxBytes without allocating an intermediate byte slice copy.
func TruncateString(s string, maxBytes int) (string, int) {
	totalLen := len(s)
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPayloadBytes
	}
	if totalLen <= maxBytes {
		return s, totalLen
	}
	return s[:maxBytes] + FormatTruncatedTrailer(totalLen), totalLen
}
