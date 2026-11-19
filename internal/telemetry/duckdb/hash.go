package duckdb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ComputeInvocationIntegrityHash generates a deterministic SHA-256 signature
// covering an invocation audit record's metadata, legacy preview, and all four
// sparse payload lifecycle fields.
func ComputeInvocationIntegrityHash(
	id string,
	ts time.Time,
	agentName, toolName, callerRole, decision string,
	latencyMs float64,
	legacyPreview, origReq, req, origResp, resp string,
) string {
	h := sha256.New()
	entry := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%.4f|%s|%s|%s|%s|%s",
		id,
		ts.UTC().Format(time.RFC3339Nano),
		agentName,
		toolName,
		callerRole,
		decision,
		latencyMs,
		legacyPreview,
		origReq,
		req,
		origResp,
		resp,
	)
	h.Write([]byte(entry))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeIntegrityHash generates a deterministic SHA-256 integrity signature for a legacy audit log entry.
func ComputeIntegrityHash(id string, ts time.Time, agentName, toolName, callerRole, decision string, latencyMs float64, preview string) string {
	return ComputeInvocationIntegrityHash(id, ts, agentName, toolName, callerRole, decision, latencyMs, preview, "", "", "", "")
}
