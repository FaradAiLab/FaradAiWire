package duckdb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

const auditHMACKeyEnv = "FARADAI_WIRE_AUDIT_HMAC_KEY"

// ResolveAuditHMACKey returns the optional HMAC key from FARADAI_WIRE_AUDIT_HMAC_KEY.
// When empty, audit records use canonical v2 SHA-256 digests cleanly without external config.
func ResolveAuditHMACKey() []byte {
	if raw := os.Getenv(auditHMACKeyEnv); raw != "" {
		return []byte(raw)
	}
	return nil
}

// ComputeV2Digest encodes every field unambiguously with explicit byte lengths (<len>:<value>\n)
// and computes either v2:hmac-sha256:<hex> (when hmacKey is non-empty) or v2:sha256:<hex>.
func ComputeV2Digest(hmacKey []byte, fields ...string) (digest string, hashVer string) {
	writeLenPrefixed := func(w func([]byte) (int, error)) {
		for _, field := range fields {
			_, _ = w([]byte(fmt.Sprintf("%d:%s\n", len(field), field)))
		}
	}
	if len(hmacKey) > 0 {
		mac := hmac.New(sha256.New, hmacKey)
		writeLenPrefixed(mac.Write)
		return "v2:hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), "v2-hmac"
	}
	sum := sha256.New()
	writeLenPrefixed(sum.Write)
	return "v2:sha256:" + hex.EncodeToString(sum.Sum(nil)), "v2"
}

// ComputeToolLogHashV2 computes the canonical length-prefixed integrity digest for a tool_audit_logs row.
func ComputeToolLogHashV2(
	hmacKey []byte,
	id string,
	ts time.Time,
	traceID, agentName, releaseVer, toolName, callerRole, userID, clientIP, apiKeyID, pathType string,
	decision, matchedRule string,
	errCode int,
	errMsg string,
	latencyMs float64,
	preview, origReq, req, origResp, resp string,
	humanApproved bool,
	approvedBy, approvalChannel string,
) (string, string) {
	return ComputeV2Digest(
		hmacKey,
		id,
		ts.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		traceID,
		agentName,
		releaseVer,
		toolName,
		callerRole,
		userID,
		clientIP,
		apiKeyID,
		pathType,
		decision,
		matchedRule,
		strconv.Itoa(errCode),
		errMsg,
		fmt.Sprintf("%.4f", latencyMs),
		preview,
		origReq,
		req,
		origResp,
		resp,
		strconv.FormatBool(humanApproved),
		approvedBy,
		approvalChannel,
	)
}

// ComputeToolResponseHashV2 computes the canonical length-prefixed integrity digest for a tool_audit_responses row.
func ComputeToolResponseHashV2(
	hmacKey []byte,
	invocationID, traceID string,
	ts time.Time,
	respDecision, matchedRule string,
	errCode int,
	auditedRules, errMsg string,
	latencyMs float64,
	outputBytes int,
	preview, origPreview, origResp, resp string,
) (string, string) {
	return ComputeV2Digest(
		hmacKey,
		invocationID,
		traceID,
		ts.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		respDecision,
		matchedRule,
		strconv.Itoa(errCode),
		auditedRules,
		errMsg,
		fmt.Sprintf("%.4f", latencyMs),
		strconv.Itoa(outputBytes),
		preview,
		origPreview,
		origResp,
		resp,
	)
}

// ComputeSecurityHashV2 computes the canonical length-prefixed integrity digest for a security_audit_logs row.
func ComputeSecurityHashV2(
	hmacKey []byte,
	id string,
	ts time.Time,
	eventType, actorID, actorRole, clientIP, resourceType, resourceID, action, outcome, reason, metaJSON string,
) (string, string) {
	return ComputeV2Digest(
		hmacKey,
		id,
		ts.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		eventType,
		actorID,
		actorRole,
		clientIP,
		resourceType,
		resourceID,
		action,
		outcome,
		reason,
		metaJSON,
	)
}

// ComputeInvocationIntegrityHash preserves the legacy v1 "|" SHA-256 signature verification helper
// for historical rows created before v2 length-prefixed digests (SEC-031).
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

// ComputeIntegrityHash generates a legacy v1 SHA-256 integrity signature for compatibility tests.
func ComputeIntegrityHash(id string, ts time.Time, agentName, toolName, callerRole, decision string, latencyMs float64, preview string) string {
	return ComputeInvocationIntegrityHash(id, ts, agentName, toolName, callerRole, decision, latencyMs, preview, "", "", "", "")
}
