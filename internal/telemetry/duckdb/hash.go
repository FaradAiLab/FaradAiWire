package duckdb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ComputeIntegrityHash generates a deterministic SHA-256 integrity signature for an audit log entry.
func ComputeIntegrityHash(id string, ts time.Time, agentName, toolName, callerRole, decision string, latencyMs float64, preview string) string {
	h := sha256.New()
	entry := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%.4f|%s",
		id,
		ts.UTC().Format(time.RFC3339Nano),
		agentName,
		toolName,
		callerRole,
		decision,
		latencyMs,
		preview,
	)
	h.Write([]byte(entry))
	return hex.EncodeToString(h.Sum(nil))
}
