package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

// SecurityAuditEventLogger is an alias to filter.SecurityAuditLogger for control-plane security audit sinks.
type SecurityAuditEventLogger = filter.SecurityAuditLogger

type adminActorCtxKey struct{}

// verifiedAdminActor carries cryptographically verified caller identity established by admin middleware.
type verifiedAdminActor struct {
	ActorID   string
	ActorRole string
	ClientIP  string
}

var secEventFallbackSeq atomic.Uint64

func withVerifiedAdminActor(r *http.Request, actor verifiedAdminActor) *http.Request {
	if r == nil {
		return nil
	}
	return r.WithContext(context.WithValue(r.Context(), adminActorCtxKey{}, actor))
}

func adminActorFromRequest(r *http.Request) verifiedAdminActor {
	if r != nil {
		if actor, ok := r.Context().Value(adminActorCtxKey{}).(verifiedAdminActor); ok && actor.ActorID != "" {
			return actor
		}
		return verifiedAdminActor{
			ActorID:   "local-operator",
			ActorRole: "admin",
			ClientIP:  clientIPFromRequest(r),
		}
	}
	return verifiedAdminActor{
		ActorID:   "local-operator",
		ActorRole: "admin",
	}
}

func apiKeyIDFromActor(actorID string) string {
	switch actorID {
	case "", "local-operator", "env:admin_token", "legacy:session", "anonymous":
		return ""
	default:
		return actorID
	}
}

func sanitizedAuditResourceID(raw string) string {
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	return raw
}

func sanitizeAuditMetadata(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	out := make(map[string]any, len(meta))
	for k, v := range meta {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "secret") ||
			strings.Contains(lk, "password") ||
			strings.Contains(lk, "raw_key") ||
			strings.Contains(lk, "token") ||
			lk == "authorization" ||
			lk == "api_key" {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

func nextSecurityEventID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return "sec-" + hex.EncodeToString(buf[:])
	}
	seq := secEventFallbackSeq.Add(1)
	return fmt.Sprintf("sec-%d-%d", time.Now().UnixNano(), seq)
}

func (a *AdminServer) logSecurityAudit(r *http.Request, eventType, action, resourceType, resourceID, outcome, reason string, metadata map[string]any) {
	actor := adminActorFromRequest(r)
	a.logSecurityAuditAs(r, actor.ActorID, actor.ActorRole, eventType, action, resourceType, resourceID, outcome, reason, metadata)
}

func (a *AdminServer) logSecurityAuditAs(r *http.Request, actorID, actorRole, eventType, action, resourceType, resourceID, outcome, reason string, metadata map[string]any) {
	loggers := a.getSecurityAuditLoggers()
	if len(loggers) == 0 {
		return
	}

	var clientIP, traceID string
	if r != nil {
		clientIP = clientIPFromRequest(r)
		traceID = strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if traceID == "" && actorID != "" {
			if actor, ok := r.Context().Value(adminActorCtxKey{}).(verifiedAdminActor); ok && actor.ClientIP != "" {
				clientIP = actor.ClientIP
			}
		}
	}

	ev := &filter.SecurityAuditEvent{
		ID:           nextSecurityEventID(),
		TraceID:      traceID,
		Timestamp:    time.Now().UTC(),
		EventType:    eventType,
		ActorID:      actorID,
		ActorRole:    actorRole,
		ClientIP:     clientIP,
		ResourceType: resourceType,
		ResourceID:   sanitizedAuditResourceID(resourceID),
		Action:       action,
		Outcome:      outcome,
		Reason:       sanitizedAuditResourceID(reason),
		Metadata:     sanitizeAuditMetadata(metadata),
	}

	for _, l := range loggers {
		if l != nil {
			l.LogSecurityEvent(ev)
		}
	}
}
