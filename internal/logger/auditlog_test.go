package logger_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
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
	if len(lines) != 3 {
		t.Fatalf("expected 1 segment_header + 2 log lines (3 total), got %d:\n%s", len(lines), string(data))
	}

	var hdr struct {
		Type       string `json:"type"`
		AnchorHash string `json:"anchor_hash"`
		HashMode   string `json:"hash_mode"`
		SegIndex   int    `json:"segment_index"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatalf("unmarshal segment_header: %v", err)
	}
	if hdr.Type != "segment_header" || hdr.AnchorHash == "" {
		t.Fatalf("invalid segment_header: %+v", hdr)
	}

	var e1, e2 struct {
		ID          string `json:"id"`
		ToolName    string `json:"tool_name"`
		PrevHash    string `json:"prev_hash"`
		EntryHash   string `json:"entry_hash"`
		HashVersion string `json:"hash_version"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &e1); err != nil {
		t.Fatalf("unmarshal entry 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &e2); err != nil {
		t.Fatalf("unmarshal entry 2: %v", err)
	}
	if e1.ToolName != "fetch_records" || e2.ToolName != "delete_system" {
		t.Fatalf("unexpected tools: e1=%q e2=%q", e1.ToolName, e2.ToolName)
	}
	if e1.PrevHash != hdr.AnchorHash || e2.PrevHash != e1.EntryHash || e1.EntryHash == "" || e2.EntryHash == "" {
		t.Fatalf("broken JSONL hash chain: hdr=%q e1=(%q->%q) e2=(%q->%q)", hdr.AnchorHash, e1.PrevHash, e1.EntryHash, e2.PrevHash, e2.EntryHash)
	}
	if e1.HashVersion != "v2" {
		t.Fatalf("HashVersion = %q, want v2", e1.HashVersion)
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

func TestFileAuditLogger_StripsLocalVaultSecrets(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "redacted_only.jsonl")

	auditLog, err := logger.NewFileAuditLogger(logPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	secret := "sk-live-secret-token-99999"
	auditLog.LogEvent(&filter.AuditEvent{
		ID:               "evt-secret",
		Timestamp:        time.Now(),
		Decision:         filter.DecisionBlocked,
		FilterName:       "dlp",
		MatchedRule:      "dlp",
		Message:          "secret detected",
		RawPayload:       "[REDACTED - Blocked by dlp: secret detected]",
		OriginalPayload:  secret,
		OriginalRequest:  `{"token":"` + secret + `"}`,
		OriginalResponse: `{"leak":"` + secret + `"}`,
	})
	if err := auditLog.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, secret) {
		t.Fatalf("ZERO-DLP BLEED: flat JSONL contained plaintext secret %q", secret)
	}
	if !strings.Contains(content, "[REDACTED - Blocked by dlp") {
		t.Fatalf("expected redaction notice in JSONL, got %s", content)
	}
}

func TestFileAuditLogger_AsyncSaturationAndConcurrency(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "async_saturation.jsonl")

	auditLog, err := logger.NewFileAuditLoggerWithOptions(
		logPath,
		logger.WithBufferSize(8),
	)
	if err != nil {
		t.Fatalf("NewFileAuditLoggerWithOptions: %v", err)
	}

	var wg sync.WaitGroup
	start := time.Now()
	const goroutines = 8
	const perG = 200
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if i%2 == 0 {
					auditLog.LogEvent(&filter.AuditEvent{
						ID:        fmt.Sprintf("ev-%d-%d", gid, i),
						Timestamp: time.Now(),
						Decision:  "ALLOWED",
						ToolName:  "concurrent_tool",
					})
				} else {
					auditLog.LogSecurityEvent(&filter.SecurityAuditEvent{
						ID:        fmt.Sprintf("sec-%d-%d", gid, i),
						Timestamp: time.Now(),
						EventType: "admin_auth_success",
						ActorID:   "admin-1",
						Outcome:   "allowed",
					})
				}
			}
		}(g)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if err := auditLog.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Post-Close calls must be no-op and never panic
	auditLog.LogEvent(&filter.AuditEvent{ID: "after-close"})
	auditLog.LogSecurityEvent(&filter.SecurityAuditEvent{ID: "sec-after-close"})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	nonHeaderLines := 0
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if ln != "" && !strings.Contains(ln, `"segment_header"`) {
			nonHeaderLines++
		}
	}
	dropped := auditLog.DroppedEvents()
	if uint64(nonHeaderLines)+dropped != goroutines*perG {
		t.Fatalf("written (%d) + dropped (%d) = %d, want %d (elapsed=%v)", nonHeaderLines, dropped, uint64(nonHeaderLines)+dropped, goroutines*perG, elapsed)
	}
}

func TestFileAuditLogger_RotationPruningAndSegmentAnchors(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "faradai_audit.jsonl")

	op := settings.DefaultOperationalSettings()
	op.Maintenance.AuditJSONLMaxFiles = 3
	op.Maintenance.AuditRetentionDays = 30
	cache := settings.NewCache(op)

	// Create a stale rotated file from 45 days ago that should be pruned
	stalePath := filepath.Join(tempDir, "faradai_audit.20200101-000000.000000.jsonl")
	if err := os.WriteFile(stalePath, []byte(`{"type":"segment_header"}`+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile stale: %v", err)
	}
	oldTime := time.Now().Add(-45 * 24 * time.Hour)
	_ = os.Chtimes(stalePath, oldTime, oldTime)

	auditLog, err := logger.NewFileAuditLoggerWithOptions(
		logPath,
		logger.WithMaxSizeBytes(450),
		logger.WithSettingsCache(cache),
	)
	if err != nil {
		t.Fatalf("NewFileAuditLoggerWithOptions: %v", err)
	}

	for i := 0; i < 18; i++ {
		if i%3 == 0 {
			auditLog.LogSecurityEvent(&filter.SecurityAuditEvent{
				ID:           fmt.Sprintf("sec-rot-%02d", i),
				Timestamp:    time.Now(),
				EventType:    "settings_mutated",
				ActorID:      "env:admin_token",
				ResourceType: "settings",
				ResourceID:   "maintenance.audit_jsonl_max_files",
				Action:       "settings_mutate",
				Outcome:      "allowed",
			})
		} else {
			auditLog.LogEvent(&filter.AuditEvent{
				ID:          fmt.Sprintf("evt-rot-%02d", i),
				Timestamp:   time.Now(),
				Decision:    "ALLOWED",
				ToolName:    "rotate_tool",
				RawPayload:  strings.Repeat("x", 180),
				FilterName:  "pipeline",
				MatchedRule: "ok",
			})
		}
	}

	if err := auditLog.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify stale 45-day file was pruned
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("expected stale segment %s to be pruned", stalePath)
	}

	matches, err := filepath.Glob(filepath.Join(tempDir, "faradai_audit*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) > 3 {
		t.Fatalf("expected <= max_files (3) segments, got %d: %v", len(matches), matches)
	}
	if len(matches) < 2 {
		t.Fatalf("expected rotation to produce >= 2 segments, got %d", len(matches))
	}

	// Verify surviving segments start with valid segment_header and continuous prev_segment_tail_hash linking
	// Active file is last in chronological order
	var tailHashByFile []string
	var ordered []string
	for _, m := range matches {
		if m != logPath {
			ordered = append(ordered, m)
		}
	}
	ordered = append(ordered, logPath)

	for idx, segPath := range ordered {
		raw, rErr := os.ReadFile(segPath)
		if rErr != nil {
			t.Fatalf("ReadFile(%s): %v", segPath, rErr)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) < 2 {
			t.Fatalf("expected header + >= 1 entry in %s, got %d lines", segPath, len(lines))
		}
		var hdr struct {
			Type                string `json:"type"`
			PrevSegmentTailHash string `json:"prev_segment_tail_hash"`
			AnchorHash          string `json:"anchor_hash"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil || hdr.Type != "segment_header" || hdr.AnchorHash == "" {
			t.Fatalf("invalid segment_header in %s: %s", segPath, lines[0])
		}
		if idx > 0 && hdr.PrevSegmentTailHash != tailHashByFile[idx-1] {
			t.Fatalf("segment %s prev_segment_tail_hash = %q, want %q", segPath, hdr.PrevSegmentTailHash, tailHashByFile[idx-1])
		}
		var last struct {
			EntryHash string `json:"entry_hash"`
		}
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || last.EntryHash == "" {
			t.Fatalf("missing tail entry_hash in %s: %s", segPath, lines[len(lines)-1])
		}
		tailHashByFile = append(tailHashByFile, last.EntryHash)
	}
}
