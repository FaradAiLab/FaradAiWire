package logger

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SegmentVerifyError describes a tamper-evidence or format violation within an audit JSONL segment.
type SegmentVerifyError struct {
	Segment string `json:"segment"`
	Line    int    `json:"line,omitempty"`
	Reason  string `json:"reason"`
}

// JSONLVerifyReport summarizes tamper-evidence verification across all surviving JSONL audit segments.
type JSONLVerifyReport struct {
	Valid           bool                 `json:"valid"`
	SegmentsChecked int                  `json:"segments_checked"`
	EntriesChecked  int                  `json:"entries_checked"`
	HMACEnabled     bool                 `json:"hmac_enabled"`
	BrokenSegments  []SegmentVerifyError `json:"broken_segments"`
}

// VerifyAuditJSONL verifies segment headers, cryptographic anchor/entry hashes, and inter-segment chains
// across active and rotated JSONL audit log files without flagging oldest-segment retention pruning.
func VerifyAuditJSONL(activePath string, hmacKey []byte) (*JSONLVerifyReport, error) {
	if len(hmacKey) == 0 {
		if envKey := os.Getenv("FARADAI_WIRE_AUDIT_HMAC_KEY"); envKey != "" {
			hmacKey = []byte(envKey)
		}
	}

	report := &JSONLVerifyReport{
		Valid:          true,
		HMACEnabled:    len(hmacKey) > 0,
		BrokenSegments: []SegmentVerifyError{},
	}

	segments, err := ListAuditSegments(activePath)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit JSONL segments: %w", err)
	}
	if len(segments) == 0 {
		return report, nil
	}

	var prevSegTailHash string
	var prevSegIndex int

	for segPos, segPath := range segments {
		report.SegmentsChecked++
		segName := filepath.Base(segPath)
		tailHash, segIdx, entries, segErr := verifySingleSegment(segPath, segPos, prevSegIndex, prevSegTailHash, hmacKey)
		report.EntriesChecked += entries
		if segErr != nil {
			segErr.Segment = segName
			report.BrokenSegments = append(report.BrokenSegments, *segErr)
			report.Valid = false
		}
		prevSegTailHash = tailHash
		prevSegIndex = segIdx
	}

	return report, nil
}

func verifySingleSegment(
	segPath string,
	segPos int,
	prevSegIndex int,
	prevSegTailHash string,
	hmacKey []byte,
) (tailHash string, segIndex int, entries int, fail *SegmentVerifyError) {
	file, err := os.Open(segPath)
	if err != nil {
		return "", 0, 0, &SegmentVerifyError{Reason: "failed to open segment: " + err.Error()}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxScannerLineBytes)

	lineNum := 0
	expectedPrevHash := ""
	expectedHashMode := "sha256-v2"
	if len(hmacKey) > 0 {
		expectedHashMode = "hmac-sha256-v2"
	}

	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		lineNum++

		if lineNum == 1 {
			var hdr SegmentHeader
			if uErr := json.Unmarshal([]byte(raw), &hdr); uErr != nil || (hdr.Type != "segment_header" && hdr.RecordType != "segment_header") {
				return "", 0, 0, &SegmentVerifyError{
					Line:   lineNum,
					Reason: "missing or invalid segment_header on first line",
				}
			}
			if hdr.HashMode != expectedHashMode {
				return "", hdr.SegmentIndex, 0, &SegmentVerifyError{
					Line:   lineNum,
					Reason: fmt.Sprintf("hash_mode mismatch: got %q, want %q", hdr.HashMode, expectedHashMode),
				}
			}
			expectedAnchor := ComputeSegmentAnchorHash(hmacKey, hdr)
			if subtle.ConstantTimeCompare([]byte(hdr.AnchorHash), []byte(expectedAnchor)) != 1 {
				return "", hdr.SegmentIndex, 0, &SegmentVerifyError{
					Line:   lineNum,
					Reason: "segment_header anchor_hash mismatch",
				}
			}
			if segPos > 0 {
				if hdr.SegmentIndex != prevSegIndex+1 {
					return "", hdr.SegmentIndex, 0, &SegmentVerifyError{
						Line:   lineNum,
						Reason: fmt.Sprintf("missing intermediate segment between index %d and %d", prevSegIndex, hdr.SegmentIndex),
					}
				}
				if prevSegTailHash != "" && subtle.ConstantTimeCompare([]byte(hdr.PrevSegmentTailHash), []byte(prevSegTailHash)) != 1 {
					return "", hdr.SegmentIndex, 0, &SegmentVerifyError{
						Line:   lineNum,
						Reason: "prev_segment_tail_hash does not match preceding segment tail",
					}
				}
			}
			segIndex = hdr.SegmentIndex
			expectedPrevHash = hdr.AnchorHash
			tailHash = hdr.AnchorHash
			continue
		}

		var entry JSONLAuditLine
		if uErr := json.Unmarshal([]byte(raw), &entry); uErr != nil {
			return "", segIndex, entries, &SegmentVerifyError{
				Line:   lineNum,
				Reason: "corrupted JSONL entry: " + uErr.Error(),
			}
		}
		if entry.RecordType == "" || entry.EntryHash == "" {
			return "", segIndex, entries, &SegmentVerifyError{
				Line:   lineNum,
				Reason: "missing record_type or entry_hash",
			}
		}
		if subtle.ConstantTimeCompare([]byte(entry.PrevHash), []byte(expectedPrevHash)) != 1 {
			return "", segIndex, entries, &SegmentVerifyError{
				Line:   lineNum,
				Reason: "prev_hash chain discontinuity (line deleted, reordered, or inserted)",
			}
		}

		expectedEntryHash, hErr := ComputeJSONLEntryHash(
			hmacKey,
			entry.RecordType,
			entry.HashVersion,
			entry.PrevHash,
			entry.AuditEvent,
			entry.SecurityEvent,
		)
		if hErr != nil {
			return "", segIndex, entries, &SegmentVerifyError{
				Line:   lineNum,
				Reason: "failed to compute entry hash: " + hErr.Error(),
			}
		}
		if subtle.ConstantTimeCompare([]byte(entry.EntryHash), []byte(expectedEntryHash)) != 1 {
			return "", segIndex, entries, &SegmentVerifyError{
				Line:   lineNum,
				Reason: "entry_hash mismatch (record content tampered)",
			}
		}

		entries++
		expectedPrevHash = entry.EntryHash
		tailHash = entry.EntryHash
	}

	if sErr := scanner.Err(); sErr != nil {
		return "", segIndex, entries, &SegmentVerifyError{
			Line:   lineNum,
			Reason: "scanner read error: " + sErr.Error(),
		}
	}
	if lineNum == 0 {
		return "", 0, 0, &SegmentVerifyError{Reason: "empty audit segment without segment_header"}
	}
	return tailHash, segIndex, entries, nil
}
