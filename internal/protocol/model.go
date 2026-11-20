package protocol

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

// SecretMaskPlaceholder is the canonical mask marker exposed in administrative API responses.
const SecretMaskPlaceholder = "••••••"

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
	Type          string            `json:"type"`                     // "stdio", "sse", "http"
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
			clone.Env[i] = MaskEnvString(envStr)
		}
	}

	if p.AuthToken != "" {
		clone.AuthToken = MaskSecretValue(p.AuthToken)
	}

	if len(p.Headers) > 0 {
		clone.Headers = make(map[string]string, len(p.Headers))
		for k, v := range p.Headers {
			clone.Headers[k] = MaskHeaderValue(k, v)
		}
	}

	// Redact embedded basic auth credentials if present in URL
	clone.URLOrCommand = RedactURLCredentials(clone.URLOrCommand)

	return &clone
}

// RedactURLCredentials strips embedded userinfo credentials from URL strings.
func RedactURLCredentials(raw string) string {
	if !strings.Contains(raw, "://") {
		return raw
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.User != nil {
		return parsed.Redacted()
	}
	return raw
}

func isSingleEnvPlaceholder(val string) bool {
	if !strings.HasPrefix(val, "${") || !strings.HasSuffix(val, "}") || len(val) <= 3 {
		return false
	}
	inner := val[2 : len(val)-1]
	return !strings.ContainsAny(inner, "{}$ \t\r\n")
}

// MaskSecretValue redacts secret tokens while preserving prefix and suffix for debuggability.
func MaskSecretValue(val string) string {
	if val == "" {
		return ""
	}
	if isSingleEnvPlaceholder(val) {
		return val
	}
	if len(val) <= 6 {
		return SecretMaskPlaceholder
	}
	prefix := val[:3]
	suffix := val[len(val)-2:]
	return fmt.Sprintf("%s%s%s", prefix, SecretMaskPlaceholder, suffix)
}

// PreserveMaskedSecret returns existing when incoming contains SecretMaskPlaceholder
// (or is empty when fillWhenEmpty is true); otherwise incoming is returned unchanged.
func PreserveMaskedSecret(incoming, existing string, fillWhenEmpty bool) string {
	if strings.Contains(incoming, SecretMaskPlaceholder) || (fillWhenEmpty && incoming == "") {
		return existing
	}
	return incoming
}

// MergeMaskedEnv restores masked KEY=VALUE entries in dstEnv from srcEnv while keeping
// explicitly modified unmasked values intact. When fillWhenEmpty is true and dstEnv is empty,
// a clone of srcEnv is returned.
func MergeMaskedEnv(dstEnv, srcEnv []string, fillWhenEmpty bool) []string {
	if len(dstEnv) == 0 {
		if fillWhenEmpty {
			return slices.Clone(srcEnv)
		}
		return slices.Clone(dstEnv)
	}
	if len(srcEnv) == 0 {
		return slices.Clone(dstEnv)
	}
	srcByKey := make(map[string]string, len(srcEnv))
	for _, entry := range srcEnv {
		if k, v, ok := strings.Cut(entry, "="); ok {
			srcByKey[k] = v
		}
	}
	merged := make([]string, len(dstEnv))
	for i, entry := range dstEnv {
		merged[i] = entry
		if k, v, ok := strings.Cut(entry, "="); ok && strings.Contains(v, SecretMaskPlaceholder) {
			if orig, found := srcByKey[k]; found {
				merged[i] = k + "=" + orig
			}
		}
	}
	return merged
}

// MergeMaskedHeaders restores masked header values in dstHeaders from srcHeaders while keeping
// explicitly rotated unmasked headers intact. When fillWhenEmpty is true and dstHeaders is empty,
// a clone of srcHeaders is returned.
func MergeMaskedHeaders(dstHeaders, srcHeaders map[string]string, fillWhenEmpty bool) map[string]string {
	if len(dstHeaders) == 0 {
		if fillWhenEmpty {
			return maps.Clone(srcHeaders)
		}
		return maps.Clone(dstHeaders)
	}
	merged := maps.Clone(dstHeaders)
	if len(srcHeaders) == 0 {
		return merged
	}
	for k, v := range merged {
		if strings.Contains(v, SecretMaskPlaceholder) {
			if orig, ok := srcHeaders[k]; ok {
				merged[k] = orig
			}
		}
	}
	return merged
}

// HydrateMaskedSecrets restores masked AuthToken, Env, and Headers fields from existing in place.
func (p *Protocol) HydrateMaskedSecrets(existing *Protocol) {
	if p == nil || existing == nil {
		return
	}
	p.AuthToken = PreserveMaskedSecret(p.AuthToken, existing.AuthToken, false)
	p.Env = MergeMaskedEnv(p.Env, existing.Env, false)
	p.Headers = MergeMaskedHeaders(p.Headers, existing.Headers, false)
}

// MaskHeaderValue redacts sensitive HTTP header values.
func MaskHeaderValue(key, val string) string {
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
	return MaskSecretValue(val)
}

// MaskEnvString redacts the secret value portion of a KEY=VALUE environment string.
func MaskEnvString(envStr string) string {
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

	return fmt.Sprintf("%s=%s", key, MaskSecretValue(val))
}
