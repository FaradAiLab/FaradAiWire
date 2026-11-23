package logger

import (
	"bufio"
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
)

const (
	defaultAuditQueueCapacity = 4096
	defaultAuditMaxSizeMB     = 10
	defaultAuditMaxFiles      = 10
	defaultAuditRetentionDays = 30
	maxScannerLineBytes       = 4 * 1024 * 1024 // 4 MB scanner buffer (> 1 MB minimum)
)

// SegmentHeader anchors the start of an audit JSONL segment file.
type SegmentHeader struct {
	RecordType          string    `json:"record_type"`
	Type                string    `json:"type"`
	SegmentIndex        int       `json:"segment_index"`
	CreatedAt           time.Time `json:"created_at"`
	HashMode            string    `json:"hash_mode"`
	PrevSegmentTailHash string    `json:"prev_segment_tail_hash"`
	AnchorHash          string    `json:"anchor_hash"`
}

// JSONLAuditLine represents one tool or control-plane security entry written to the audit JSONL trail.
type JSONLAuditLine struct {
	RecordType  string `json:"record_type"`
	HashVersion string `json:"hash_version,omitempty"`
	PrevHash    string `json:"prev_hash,omitempty"`
	EntryHash   string `json:"entry_hash,omitempty"`
	*filter.AuditEvent
	SecurityEvent *filter.SecurityAuditEvent `json:"security_event,omitempty"`
}

type auditWorkItem struct {
	recordType    string
	toolEvent     *filter.AuditEvent
	securityEvent *filter.SecurityAuditEvent
}

// AuditLoggerOption configures optional FileAuditLogger behavior.
type AuditLoggerOption func(*auditLoggerOptions)

type auditLoggerOptions struct {
	bufferSize    int
	maxSizeMB     int
	maxSizeBytes  int64
	maxFiles      int
	retentionDays int
	settingsCache *settings.Cache
	hmacKey       []byte
	hmacKeySet    bool
}

// WithBufferSize sets the bounded async queue capacity (defaults to 4096).
func WithBufferSize(n int) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		if n > 0 {
			o.bufferSize = n
		}
	}
}

// WithMaxSizeMB configures fallback size rotation limit in megabytes when no SettingsCache override is active.
func WithMaxSizeMB(mb int) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		if mb > 0 {
			o.maxSizeMB = mb
		}
	}
}

// WithMaxSizeBytes forces an exact byte threshold for size rotation (primarily for deterministic tests).
func WithMaxSizeBytes(bytes int64) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		if bytes > 0 {
			o.maxSizeBytes = bytes
		}
	}
}

// WithMaxFiles sets the maximum total number of retained JSONL files (active + rotated).
func WithMaxFiles(n int) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		if n > 0 {
			o.maxFiles = n
		}
	}
}

// WithRetentionDays sets the fallback retention period for pruning rotated JSONL files.
func WithRetentionDays(days int) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		if days > 0 {
			o.retentionDays = days
		}
	}
}

// WithSettingsCache binds live operational maintenance settings (max size, max files, retention days).
func WithSettingsCache(cache *settings.Cache) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		o.settingsCache = cache
	}
}

// WithHMACKey configures an explicit HMAC-SHA256 signing key for v2-hmac JSONL chains.
func WithHMACKey(key []byte) AuditLoggerOption {
	return func(o *auditLoggerOptions) {
		if len(key) > 0 {
			o.hmacKey = append([]byte(nil), key...)
			o.hmacKeySet = true
		}
	}
}

// FileAuditLogger asynchronously writes redacted, hash-chained AuditEvents and SecurityAuditEvents to rotating JSONL segments.
type FileAuditLogger struct {
	path          string
	opts          auditLoggerOptions
	settingsCache atomic.Pointer[settings.Cache]
	hmacKey       []byte

	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	ch        chan auditWorkItem
	done      chan struct{}
	closeErr  error
	dropped   atomic.Uint64

	// Worker-owned state (only accessed by background writer goroutine after initialization)
	file              *os.File
	currentSize       int64
	hasEntryInSegment bool
	segmentIndex      int
	lastHash          string
	rotateSeq         int
}

// NewFileAuditLogger opens or creates the audit log file with default 10 MB rotation and 4096 async queue.
func NewFileAuditLogger(path string) (*FileAuditLogger, error) {
	return NewFileAuditLoggerWithOptions(path)
}

// NewFileAuditLoggerWithOptions creates an asynchronous rotating hash-chained FileAuditLogger.
func NewFileAuditLoggerWithOptions(path string, options ...AuditLoggerOption) (*FileAuditLogger, error) {
	if path == "" {
		return nil, fmt.Errorf("audit log path cannot be empty")
	}

	opts := auditLoggerOptions{
		bufferSize:    defaultAuditQueueCapacity,
		maxSizeMB:     defaultAuditMaxSizeMB,
		maxFiles:      defaultAuditMaxFiles,
		retentionDays: defaultAuditRetentionDays,
	}
	for _, fn := range options {
		if fn != nil {
			fn(&opts)
		}
	}

	var hmacKey []byte
	if opts.hmacKeySet {
		hmacKey = opts.hmacKey
	} else if envKey := os.Getenv("FARADAI_WIRE_AUDIT_HMAC_KEY"); envKey != "" {
		hmacKey = []byte(envKey)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory %s: %w", dir, err)
	}

	f := &FileAuditLogger{
		path:    path,
		opts:    opts,
		hmacKey: hmacKey,
		ch:      make(chan auditWorkItem, opts.bufferSize),
		done:    make(chan struct{}),
	}
	if opts.settingsCache != nil {
		f.settingsCache.Store(opts.settingsCache)
	}

	if err := f.initActiveSegment(); err != nil {
		return nil, err
	}

	go f.worker()
	return f, nil
}

// SetSettingsCache attaches or replaces the live SettingsCache used for dynamic rotation/retention bounds.
func (f *FileAuditLogger) SetSettingsCache(cache *settings.Cache) {
	if f == nil {
		return
	}
	f.settingsCache.Store(cache)
}

// DroppedEvents returns the cumulative count of events dropped due to bounded queue saturation.
func (f *FileAuditLogger) DroppedEvents() uint64 {
	if f == nil {
		return 0
	}
	return f.dropped.Load()
}

// LogEvent redacts sensitive fields and asynchronously enqueues a tool AuditEvent without blocking the hot path.
func (f *FileAuditLogger) LogEvent(event *filter.AuditEvent) {
	if f == nil || event == nil {
		return
	}
	redacted := event.RedactedCopy()
	f.enqueue(auditWorkItem{
		recordType: "tool_audit",
		toolEvent:  redacted,
	})
}

// LogSecurityEvent clones and redacts sensitive metadata and asynchronously enqueues a SecurityAuditEvent.
func (f *FileAuditLogger) LogSecurityEvent(event *filter.SecurityAuditEvent) {
	if f == nil || event == nil {
		return
	}
	sanitized := sanitizeSecurityAuditEventCopy(event)
	f.enqueue(auditWorkItem{
		recordType:    "security_audit",
		securityEvent: sanitized,
	})
}

func (f *FileAuditLogger) enqueue(item auditWorkItem) {
	f.mu.RLock()
	if f.closed {
		f.mu.RUnlock()
		return
	}
	select {
	case f.ch <- item:
	default:
		f.dropped.Add(1)
	}
	f.mu.RUnlock()
}

// Close flushes all buffered audit entries, syncs OS buffers to disk, and closes the file idempotently.
func (f *FileAuditLogger) Close() error {
	if f == nil {
		return nil
	}
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		close(f.ch)
		f.mu.Unlock()
		<-f.done
	})
	return f.closeErr
}

func (f *FileAuditLogger) worker() {
	defer close(f.done)

	for item := range f.ch {
		if err := f.writeItem(item); err != nil {
			slog.Error("Failed to write audit JSONL record", slog.String("error", err.Error()))
		}
	}

	if f.file != nil {
		syncErr := f.file.Sync()
		closeErr := f.file.Close()
		f.file = nil
		if syncErr != nil {
			f.closeErr = syncErr
		} else {
			f.closeErr = closeErr
		}
	}
}

func (f *FileAuditLogger) effectiveLimits() (maxBytes int64, maxFiles int, retentionDays int) {
	maxSizeMB := cmp.Or(f.opts.maxSizeMB, defaultAuditMaxSizeMB)
	maxFiles = cmp.Or(f.opts.maxFiles, defaultAuditMaxFiles)
	retentionDays = cmp.Or(f.opts.retentionDays, defaultAuditRetentionDays)

	if cache := f.settingsCache.Load(); cache != nil {
		snap := cache.Get()
		if snap.Maintenance.AuditJSONLMaxSizeMB > 0 {
			maxSizeMB = snap.Maintenance.AuditJSONLMaxSizeMB
		}
		if snap.Maintenance.AuditJSONLMaxFiles > 0 {
			maxFiles = snap.Maintenance.AuditJSONLMaxFiles
		}
		if snap.Maintenance.AuditRetentionDays > 0 {
			retentionDays = snap.Maintenance.AuditRetentionDays
		}
	}

	if f.opts.maxSizeBytes > 0 {
		maxBytes = f.opts.maxSizeBytes
	} else {
		maxBytes = int64(maxSizeMB) * 1024 * 1024
	}
	return maxBytes, maxFiles, retentionDays
}

func (f *FileAuditLogger) initActiveSegment() error {
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log file %s: %w", f.path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to stat audit log file %s: %w", f.path, err)
	}
	f.file = file
	f.currentSize = info.Size()

	if info.Size() == 0 {
		return f.writeSegmentHeader("")
	}

	segIdx, tailHash, hasEntry, readErr := inspectExistingSegmentTail(f.path)
	if readErr == nil && tailHash != "" {
		f.segmentIndex = segIdx
		f.lastHash = tailHash
		f.hasEntryInSegment = hasEntry
		return nil
	}

	// Empty-chain fallback when resuming an unchained pre-upgrade JSONL segment
	f.segmentIndex = 0
	f.hasEntryInSegment = true
	return nil
}

func inspectExistingSegmentTail(path string) (segmentIndex int, tailHash string, hasEntry bool, err error) {
	rf, err := os.Open(path)
	if err != nil {
		return 0, "", false, err
	}
	defer rf.Close()

	scanner := bufio.NewScanner(rf)
	scanner.Buffer(make([]byte, 64*1024), maxScannerLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var probe struct {
			RecordType   string `json:"record_type"`
			Type         string `json:"type"`
			SegmentIndex int    `json:"segment_index"`
			AnchorHash   string `json:"anchor_hash"`
			EntryHash    string `json:"entry_hash"`
		}
		if json.Unmarshal([]byte(line), &probe) != nil {
			continue
		}
		if probe.RecordType == "segment_header" || probe.Type == "segment_header" {
			segmentIndex = probe.SegmentIndex
			if probe.AnchorHash != "" {
				tailHash = probe.AnchorHash
			}
		} else if probe.EntryHash != "" {
			hasEntry = true
			tailHash = probe.EntryHash
		}
	}
	if sErr := scanner.Err(); sErr != nil {
		return segmentIndex, tailHash, hasEntry, sErr
	}
	return segmentIndex, tailHash, hasEntry, nil
}

func (f *FileAuditLogger) writeSegmentHeader(prevTailHash string) error {
	hashMode, _ := f.hashModeLabels()
	hdr := SegmentHeader{
		RecordType:          "segment_header",
		Type:                "segment_header",
		SegmentIndex:        f.segmentIndex,
		CreatedAt:           time.Now().UTC(),
		HashMode:            hashMode,
		PrevSegmentTailHash: prevTailHash,
	}
	hdr.AnchorHash = ComputeSegmentAnchorHash(f.hmacKey, hdr)

	b, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	n, err := f.file.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	f.currentSize += int64(n)
	f.lastHash = hdr.AnchorHash
	f.hasEntryInSegment = false
	return nil
}

func (f *FileAuditLogger) hashModeLabels() (mode string, version string) {
	if len(f.hmacKey) > 0 {
		return "hmac-sha256-v2", "v2-hmac"
	}
	return "sha256-v2", "v2"
}

func (f *FileAuditLogger) writeItem(item auditWorkItem) error {
	encoded, entryHash, err := f.marshalChainedEntry(item)
	if err != nil {
		return err
	}

	maxBytes, maxFiles, retentionDays := f.effectiveLimits()
	if f.file != nil && maxBytes > 0 && f.hasEntryInSegment && f.currentSize+int64(len(encoded)+1) > maxBytes {
		if err := f.rotateSegment(maxFiles, retentionDays); err != nil {
			return err
		}
		// Recompute chained entry under the new segment's anchor PrevHash
		encoded, entryHash, err = f.marshalChainedEntry(item)
		if err != nil {
			return err
		}
	}

	if f.file == nil {
		return fmt.Errorf("audit log file handle is nil")
	}

	n, err := f.file.Write(append(encoded, '\n'))
	if err != nil {
		return err
	}
	f.currentSize += int64(n)
	f.lastHash = entryHash
	f.hasEntryInSegment = true
	return nil
}

func (f *FileAuditLogger) marshalChainedEntry(item auditWorkItem) ([]byte, string, error) {
	_, hashVer := f.hashModeLabels()
	entryHash, err := ComputeJSONLEntryHash(f.hmacKey, item.recordType, hashVer, f.lastHash, item.toolEvent, item.securityEvent)
	if err != nil {
		return nil, "", err
	}

	envelope := JSONLAuditLine{
		RecordType:    item.recordType,
		HashVersion:   hashVer,
		PrevHash:      f.lastHash,
		EntryHash:     entryHash,
		AuditEvent:    item.toolEvent,
		SecurityEvent: item.securityEvent,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", err
	}
	return encoded, entryHash, nil
}

func (f *FileAuditLogger) rotateSegment(maxFiles, retentionDays int) error {
	prevTail := f.lastHash

	if f.file != nil {
		_ = f.file.Sync()
		_ = f.file.Close()
		f.file = nil
	}

	f.rotateSeq++
	rotatedPath := buildRotatedSegmentPath(f.path, time.Now().UTC(), f.rotateSeq)
	if err := os.Rename(f.path, rotatedPath); err != nil {
		// Reopen original handle on rename error to keep logging rather than silently failing closed
		reopen, rErr := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if rErr == nil {
			f.file = reopen
		}
		return fmt.Errorf("failed to rotate audit log %s -> %s: %w", f.path, rotatedPath, err)
	}

	nextFile, err := os.OpenFile(f.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create successor audit log segment %s: %w", f.path, err)
	}
	f.file = nextFile
	f.currentSize = 0
	f.segmentIndex++

	if err := f.writeSegmentHeader(prevTail); err != nil {
		return err
	}

	pruneRotatedSegments(f.path, maxFiles, retentionDays)
	return nil
}

func buildRotatedSegmentPath(activePath string, now time.Time, seq int) string {
	dir := filepath.Dir(activePath)
	base := filepath.Base(activePath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, fmt.Sprintf("%s.%s.%06d%s", stem, now.Format("20060102-150405"), seq, ext))
}

func pruneRotatedSegments(activePath string, maxFiles, retentionDays int) {
	rotated, err := listRotatedSegmentsAsc(activePath)
	if err != nil {
		return
	}

	if retentionDays > 0 {
		cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
		var kept []string
		for _, p := range rotated {
			info, sErr := os.Stat(p)
			if sErr == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(p)
				continue
			}
			kept = append(kept, p)
		}
		rotated = kept
	}

	if maxFiles > 0 {
		// Active file counts as 1 toward maxFiles total segments
		maxRotated := maxFiles - 1
		if maxRotated < 0 {
			maxRotated = 0
		}
		for len(rotated) > maxRotated {
			oldest := rotated[0]
			rotated = rotated[1:]
			_ = os.Remove(oldest)
		}
	}
}

func listRotatedSegmentsAsc(activePath string) ([]string, error) {
	dir := filepath.Dir(activePath)
	base := filepath.Base(activePath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	prefix := stem + "."

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var rotated []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == base {
			continue
		}
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ext) {
			rotated = append(rotated, filepath.Join(dir, name))
		}
	}
	sort.Strings(rotated)
	return rotated, nil
}

// ListAuditSegments returns active and rotated JSONL segment paths in chronological order (oldest first, active last).
func ListAuditSegments(activePath string) ([]string, error) {
	if activePath == "" {
		return nil, nil
	}
	rotated, err := listRotatedSegmentsAsc(activePath)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rotated)+1)
	out = append(out, rotated...)
	if _, sErr := os.Stat(activePath); sErr == nil {
		out = append(out, activePath)
	}
	return out, nil
}

// ListAuditSegmentsDesc returns active and rotated JSONL segment paths in reverse chronological order (newest/active first).
func ListAuditSegmentsDesc(activePath string) ([]string, error) {
	asc, err := ListAuditSegments(activePath)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(asc)-1; i < j; i, j = i+1, j-1 {
		asc[i], asc[j] = asc[j], asc[i]
	}
	return asc, nil
}

// ComputeSegmentAnchorHash computes the SHA-256 or HMAC-SHA256 anchor digest for a segment_header record.
func ComputeSegmentAnchorHash(hmacKey []byte, hdr SegmentHeader) string {
	return canonicalDigest(
		hmacKey,
		"segment_header",
		strconv.Itoa(hdr.SegmentIndex),
		hdr.CreatedAt.UTC().Format(time.RFC3339Nano),
		hdr.HashMode,
		hdr.PrevSegmentTailHash,
	)
}

// ComputeJSONLEntryHash computes the tamper-evident chained digest for a single JSONL audit or security entry.
func ComputeJSONLEntryHash(
	hmacKey []byte,
	recordType string,
	hashVersion string,
	prevHash string,
	toolEvent *filter.AuditEvent,
	securityEvent *filter.SecurityAuditEvent,
) (string, error) {
	var payloadBytes []byte
	var err error
	switch recordType {
	case "security_audit":
		payloadBytes, err = json.Marshal(securityEvent)
	default:
		payloadBytes, err = json.Marshal(toolEvent)
	}
	if err != nil {
		return "", err
	}
	return canonicalDigest(hmacKey, recordType, hashVersion, prevHash, string(payloadBytes)), nil
}

func canonicalDigest(hmacKey []byte, fields ...string) string {
	var h []byte
	writeLenPrefixed := func(w func([]byte) (int, error)) {
		var lenBuf [4]byte
		for _, field := range fields {
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
			_, _ = w(lenBuf[:])
			if len(field) > 0 {
				_, _ = w([]byte(field))
			}
		}
	}
	if len(hmacKey) > 0 {
		mac := hmac.New(sha256.New, hmacKey)
		writeLenPrefixed(mac.Write)
		h = mac.Sum(nil)
	} else {
		sum := sha256.New()
		writeLenPrefixed(sum.Write)
		h = sum.Sum(nil)
	}
	return hex.EncodeToString(h)
}

func sanitizeSecurityAuditEventCopy(event *filter.SecurityAuditEvent) *filter.SecurityAuditEvent {
	if event == nil {
		return nil
	}
	cp := *event
	if idx := strings.IndexByte(cp.ResourceID, '?'); idx >= 0 {
		cp.ResourceID = cp.ResourceID[:idx]
	}
	if idx := strings.IndexByte(cp.Reason, '?'); idx >= 0 {
		cp.Reason = cp.Reason[:idx]
	}
	if len(event.Metadata) > 0 {
		meta := make(map[string]any, len(event.Metadata))
		for k, v := range event.Metadata {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "secret") ||
				strings.Contains(lk, "password") ||
				strings.Contains(lk, "raw_key") ||
				strings.Contains(lk, "token") ||
				lk == "authorization" ||
				lk == "api_key" {
				meta[k] = "[REDACTED]"
				continue
			}
			meta[k] = v
		}
		cp.Metadata = meta
	}
	return &cp
}
