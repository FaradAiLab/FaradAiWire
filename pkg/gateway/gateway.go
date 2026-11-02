// Package gateway exposes the public gateway server constructor, proxy engine, and
// security pipeline orchestration types for external Go module consumers.
package gateway

import (
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
	pkgfilter "github.com/FaradAiLab/FaradAiWire/pkg/filter"
)

// Server represents the FaradAiWire proxy engine.
type Server = gateway.Server

// Pipeline represents the security filter pipeline.
type Pipeline = filter.Pipeline

// AuditEvent represents a security audit event.
type AuditEvent = filter.AuditEvent

// UserContext represents user metadata for audit/filter.
type UserContext = filter.UserContext

// ContextKey represents context key type.
type ContextKey = filter.ContextKey

// AuditLogger represents an audit event logger.
type AuditLogger = filter.AuditLogger

// SecurityFilter is re-exported from pkg/filter.
type SecurityFilter = pkgfilter.SecurityFilter

// NewServer initializes a configured Gateway Server instance.
func NewServer(cfg *config.Config, provider config.Provider) (*Server, error) {
	return gateway.NewServer(cfg, provider)
}
