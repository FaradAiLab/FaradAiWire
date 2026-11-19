package logger

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

// FileAuditLogger implements filter.AuditLogger and writes events to a local JSONL file in an append-only, thread-safe manner.
type FileAuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

// NewFileAuditLogger opens or creates the audit log file. It creates any parent directories if they don't exist.
func NewFileAuditLogger(path string) (*FileAuditLogger, error) {
	if path == "" {
		return &FileAuditLogger{}, nil
	}

	// Create directory structure if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}

	// Open file in append-only, write-only mode (immutable log trail)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &FileAuditLogger{
		file: file,
	}, nil
}

// LogEvent writes a structured audit event to the JSONL file.
// Unmasked local-vault fields are stripped via RedactedCopy so flat logs never
// leak plaintext secrets or PII (ZERO-DLP BLEED invariant).
func (f *FileAuditLogger) LogEvent(event *filter.AuditEvent) {
	safeEvent := event.RedactedCopy()
	if safeEvent == nil {
		return
	}

	data, err := json.Marshal(safeEvent)
	if err != nil {
		slog.Error("Error marshaling audit event",
			slog.String("trace_id", safeEvent.TraceID),
			slog.String("agent", safeEvent.AgentName),
			slog.String("error", err.Error()),
		)
		return
	}

	logFallback := func() {
		slog.Info("Audit event console fallback",
			slog.String("trace_id", safeEvent.TraceID),
			slog.String("agent", safeEvent.AgentName),
			slog.String("decision", safeEvent.Decision),
			slog.String("tool", safeEvent.ToolName),
			slog.Float64("latency_ms", safeEvent.LatencyMs),
			slog.String("audit_json", string(data)),
		)
	}

	if f == nil {
		logFallback()
		return
	}

	f.mu.Lock()
	if f.file == nil {
		f.mu.Unlock()
		logFallback()
		return
	}
	line := append(data, '\n')
	_, writeErr := f.file.Write(line)
	f.mu.Unlock()

	if writeErr != nil {
		slog.Error("Error writing to audit log file",
			slog.String("trace_id", safeEvent.TraceID),
			slog.String("agent", safeEvent.AgentName),
			slog.String("error", writeErr.Error()),
		)
	}
}

// Close closes the underlying log file after syncing dirty kernel buffers to persistent storage.
func (f *FileAuditLogger) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file != nil {
		_ = f.file.Sync()
		err := f.file.Close()
		f.file = nil
		return err
	}
	return nil
}
