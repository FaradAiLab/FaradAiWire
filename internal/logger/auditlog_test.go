package logger_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
)

func TestFileAuditLogger_LifecycleAndSync(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit_test.jsonl")

	auditLog, err := logger.NewFileAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	event1 := &filter.AuditEvent{
		ID:        "evt-1",
		Timestamp: time.Now(),
		Decision:  "ALLOWED",
		ToolName:  "fetch_records",
	}
	auditLog.LogEvent(event1)

	event2 := &filter.AuditEvent{
		ID:        "evt-2",
		Timestamp: time.Now(),
		Decision:  "BLOCKED",
		ToolName:  "delete_system",
	}
	auditLog.LogEvent(event2)

	// Close should sync dirty kernel buffers and close underlying file
	if err := auditLog.Close(); err != nil {
		t.Fatalf("unexpected error closing audit logger: %v", err)
	}

	// Idempotency: second close must return nil
	if err := auditLog.Close(); err != nil {
		t.Errorf("expected idempotent second close to succeed, got: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "fetch_records") {
		t.Errorf("expected line 1 to contain fetch_records, got %s", lines[0])
	}
	if !strings.Contains(lines[1], "delete_system") {
		t.Errorf("expected line 2 to contain delete_system, got %s", lines[1])
	}
}

func TestFileAuditLogger_NilSafe(t *testing.T) {
	var nilLogger *logger.FileAuditLogger
	if err := nilLogger.Close(); err != nil {
		t.Errorf("expected nil logger close to return nil, got: %v", err)
	}
	// Calling LogEvent on nil must not panic
	nilLogger.LogEvent(&filter.AuditEvent{ID: "test"})
}
