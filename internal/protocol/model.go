package protocol

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

var (
	// ErrInvalidID indicates that the protocol identifier failed safe character validation.
	ErrInvalidID = errors.New("invalid protocol id: must be alphanumeric with dashes, dots, or underscores")
	// ErrInvalidType indicates an unsupported protocol transport type.
	ErrInvalidType = errors.New("invalid protocol type: must be 'stdio', 'sse', or 'http'")
	// ErrMissingTarget indicates that both Command and URLOrCommand are absent.
	ErrMissingTarget = errors.New("protocol requires a command (for stdio) or target URL (for sse/http)")
	// ErrProtocolNotFound indicates that the requested protocol does not exist.
	ErrProtocolNotFound = errors.New("protocol not found")
	// ErrProtocolInUse indicates that the protocol cannot be deleted because it is attached to active agents.
	ErrProtocolInUse = errors.New("protocol is in use by one or more agents")
)

// Protocol represents a Model Context Protocol backend endpoint definition.
type Protocol struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Type          string            `json:"type"` // "stdio", "sse", "http"
	TransportMode string            `json:"transport_mode,omitempty"` // "sse" or "streamable_http" — negotiated at probe time
	Command       string            `json:"command,omitempty"`
	Args          []string          `json:"args,omitempty"`
	Env           []string          `json:"env,omitempty"`
	URLOrCommand  string            `json:"url_or_command,omitempty"`
	AuthToken     string            `json:"auth_token,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	AllowedTools  []string          `json:"allowed_tools,omitempty"`
	Status        string            `json:"status,omitempty"` // "active", "unreachable", "error"
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Validate ensures that the protocol definition complies with safety and transport requirements.
func (p *Protocol) Validate() error {
	if p == nil {
		return errors.New("protocol cannot be nil")
	}

	p.ID = strings.TrimSpace(p.ID)
	if err := pathguard.ValidateSafeIdentifier(p.ID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}

	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = p.ID
	}

	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if p.Type == "" {
		// Infer type from URLOrCommand if possible
		if strings.HasPrefix(strings.ToLower(p.URLOrCommand), "http://") || strings.HasPrefix(strings.ToLower(p.URLOrCommand), "https://") {
			p.Type = "sse"
		} else {
			p.Type = "stdio"
		}
	}

	if p.Type != "stdio" && p.Type != "sse" && p.Type != "http" {
		return fmt.Errorf("%w: '%s'", ErrInvalidType, p.Type)
	}

	p.URLOrCommand = strings.TrimSpace(p.URLOrCommand)
	p.Command = strings.TrimSpace(p.Command)
	p.AuthToken = strings.TrimSpace(p.AuthToken)

	if p.Type == "stdio" && p.Command == "" && p.URLOrCommand == "" {
		return ErrMissingTarget
	}
	if (p.Type == "sse" || p.Type == "http") && p.URLOrCommand == "" {
		return ErrMissingTarget
	}

	if p.Headers != nil {
		for k := range p.Headers {
			if strings.TrimSpace(k) == "" {
				return errors.New("header name cannot be empty")
			}
		}
	}

	return nil
}

// GetResolvedEnv returns environment variable strings with dynamic `${VAR}` references expanded from the host environment.
func (p *Protocol) GetResolvedEnv() []string {
	if p == nil || len(p.Env) == 0 {
		return nil
	}
	resolved := make([]string, len(p.Env))
	for i, entry := range p.Env {
		resolved[i] = os.ExpandEnv(entry)
	}
	return resolved
}

// GetResolvedAuthToken returns the auth token with dynamic `${VAR}` references expanded from the host environment.
func (p *Protocol) GetResolvedAuthToken() string {
	if p == nil || p.AuthToken == "" {
		return ""
	}
	return os.ExpandEnv(p.AuthToken)
}

// GetResolvedHeaders returns a copy of headers with dynamic `${VAR}` references expanded from the host environment.
func (p *Protocol) GetResolvedHeaders() map[string]string {
	if p == nil || len(p.Headers) == 0 {
		return nil
	}
	resolved := make(map[string]string, len(p.Headers))
	for k, v := range p.Headers {
		resolved[k] = os.ExpandEnv(v)
	}
	return resolved
}

// MaskSecrets creates a sanitized copy of the protocol safe for exposure over administrative APIs.
// Sensitive environment variables, auth tokens, and sensitive headers are partially masked.
func (p *Protocol) MaskSecrets() *Protocol {
	if p == nil {
		return nil
	}

	clone := *p
	if len(p.Args) > 0 {
		clone.Args = make([]string, len(p.Args))
		copy(clone.Args, p.Args)
	}
	if len(p.AllowedTools) > 0 {
		clone.AllowedTools = make([]string, len(p.AllowedTools))
		copy(clone.AllowedTools, p.AllowedTools)
	}

	if len(p.Env) > 0 {
		clone.Env = make([]string, len(p.Env))
		for i, envStr := range p.Env {
			clone.Env[i] = maskEnvString(envStr)
		}
	}

	if p.AuthToken != "" {
		clone.AuthToken = maskSecretValue(p.AuthToken)
	}

	if len(p.Headers) > 0 {
		clone.Headers = make(map[string]string, len(p.Headers))
		for k, v := range p.Headers {
			clone.Headers[k] = maskHeaderValue(k, v)
		}
	}

	// Redact embedded basic auth credentials if present in URL
	if strings.Contains(clone.URLOrCommand, "://") {
		if parsed, err := url.Parse(clone.URLOrCommand); err == nil && parsed.User != nil {
			clone.URLOrCommand = parsed.Redacted()
		}
	}

	return &clone
}

// maskSecretValue redacts secret tokens while preserving prefix and suffix for debuggability.
func maskSecretValue(val string) string {
	if val == "" {
		return ""
	}
	if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
		return val
	}
	if len(val) <= 6 {
		return "••••••"
	}
	prefix := val[:3]
	suffix := val[len(val)-2:]
	return fmt.Sprintf("%s••••••%s", prefix, suffix)
}

// maskHeaderValue redacts sensitive HTTP header values.
func maskHeaderValue(key, val string) string {
	keyUpper := strings.ToUpper(key)
	isSensitive := strings.EqualFold(key, "Authorization") ||
		strings.Contains(keyUpper, "TOKEN") ||
		strings.Contains(keyUpper, "SECRET") ||
		strings.Contains(keyUpper, "KEY") ||
		strings.Contains(keyUpper, "PASS") ||
		strings.Contains(keyUpper, "AUTH") ||
		strings.Contains(keyUpper, "CREDENTIAL")

	if !isSensitive {
		return val
	}
	return maskSecretValue(val)
}

// maskEnvString redacts the secret value portion of a KEY=VALUE environment string.
func maskEnvString(envStr string) string {
	parts := strings.SplitN(envStr, "=", 2)
	if len(parts) != 2 {
		return envStr
	}

	key := parts[0]
	val := parts[1]

	keyUpper := strings.ToUpper(key)
	isSensitive := strings.Contains(keyUpper, "TOKEN") ||
		strings.Contains(keyUpper, "SECRET") ||
		strings.Contains(keyUpper, "KEY") ||
		strings.Contains(keyUpper, "PASS") ||
		strings.Contains(keyUpper, "AUTH") ||
		strings.Contains(keyUpper, "CREDENTIAL")

	if !isSensitive || val == "" {
		return envStr
	}

	return fmt.Sprintf("%s=%s", key, maskSecretValue(val))
}
