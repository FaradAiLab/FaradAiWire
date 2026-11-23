package logger_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

func TestVerifyAuditJSONL_MultiSegmentAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "faradai_audit.jsonl")

	op := settings.DefaultOperationalSettings()
	op.Maintenance.AuditJSONLMaxFiles = 3
	cache := settings.NewCache(op)

	l, err := logger.NewFileAuditLoggerWithOptions(
		logPath,
		logger.WithMaxSizeBytes(450),
		logger.WithSettingsCache(cache),
	)
	if err != nil {
		t.Fatalf("NewFileAuditLoggerWithOptions: %v", err)
	}
	for i := 0; i < 16; i++ {
		l.LogEvent(&filter.AuditEvent{
			ID:         fmt.Sprintf("ev-%02d", i),
			Timestamp:  time.Now().UTC(),
			Decision:   "ALLOWED",
			ToolName:   "verify_tool",
			RawPayload: strings.Repeat("p", 160),
		})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 1. Pruned oldest segment + surviving segments must verify cleanly
	report, err := logger.VerifyAuditJSONL(logPath, nil)
	if err != nil {
		t.Fatalf("VerifyAuditJSONL: %v", err)
	}
	if !report.Valid || report.SegmentsChecked < 2 || report.EntriesChecked == 0 || len(report.BrokenSegments) != 0 {
		t.Fatalf("expected clean multi-segment verification, got %+v", report)
	}

	// 2. Tamper one field inside the active file -> must flag broken segment
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(raw), `"ALLOWED"`, `"BLOCKED"`, 1)
	if tampered == string(raw) {
		t.Fatal("failed to locate ALLOWED in active JSONL file")
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0600); err != nil {
		t.Fatalf("WriteFile tampered: %v", err)
	}

	badReport, err := logger.VerifyAuditJSONL(logPath, nil)
	if err != nil {
		t.Fatalf("VerifyAuditJSONL tampered: %v", err)
	}
	if badReport.Valid || len(badReport.BrokenSegments) == 0 {
		t.Fatalf("expected BrokenSegments on modified entry, got %+v", badReport)
	}
}

func TestVerifyAuditJSONL_HMACAndLineDeletionOrReorder(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "hmac_audit.jsonl")
	hmacKey := []byte("jsonl-hmac-test-secret")

	l, err := logger.NewFileAuditLoggerWithOptions(logPath, logger.WithHMACKey(hmacKey))
	if err != nil {
		t.Fatalf("NewFileAuditLoggerWithOptions: %v", err)
	}
	for i := 0; i < 4; i++ {
		l.LogEvent(&filter.AuditEvent{
			ID:        fmt.Sprintf("hmac-ev-%d", i),
			Timestamp: time.Now().UTC(),
			Decision:  "ALLOWED",
			ToolName:  "t",
		})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Valid HMAC
	okRep, err := logger.VerifyAuditJSONL(logPath, hmacKey)
	if err != nil || !okRep.Valid || !okRep.HMACEnabled {
		t.Fatalf("expected valid HMAC JSONL verification, got rep=%+v err=%v", okRep, err)
	}

	// Wrong HMAC key -> invalid
	wrongRep, err := logger.VerifyAuditJSONL(logPath, []byte("wrong-key"))
	if err != nil || wrongRep.Valid || len(wrongRep.BrokenSegments) == 0 {
		t.Fatalf("expected failure with wrong HMAC key, got rep=%+v err=%v", wrongRep, err)
	}

	// Deleting a middle line breaks the chain
	raw, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected >= 5 lines, got %d", len(lines))
	}
	deleted := append(append([]string(nil), lines[:2]...), lines[3:]...)
	_ = os.WriteFile(logPath, []byte(strings.Join(deleted, "\n")+"\n"), 0600)

	delRep, err := logger.VerifyAuditJSONL(logPath, hmacKey)
	if err != nil || delRep.Valid || len(delRep.BrokenSegments) == 0 {
		t.Fatalf("expected middle line deletion to break chain, got %+v (err=%v)", delRep, err)
	}

	// Reordering two entries breaks the chain
	reordered := []string{lines[0], lines[2], lines[1], lines[3], lines[4]}
	_ = os.WriteFile(logPath, []byte(strings.Join(reordered, "\n")+"\n"), 0600)
	reordRep, err := logger.VerifyAuditJSONL(logPath, hmacKey)
	if err != nil || reordRep.Valid || len(reordRep.BrokenSegments) == 0 {
		t.Fatalf("expected line reorder to break chain, got %+v (err=%v)", reordRep, err)
	}
}
