package proxy

import (
	"cmp"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

var (
	// ErrUnauthorized is returned when an ingress request lacks valid credentials or has an invalid/revoked API key.
	ErrUnauthorized = errors.New("unauthorized: missing, invalid, or revoked API key")
	// ErrForbiddenAdminKeyOnIngress is returned when an Admin-scoped API key is presented to MCP ingress (:19410).
	ErrForbiddenAdminKeyOnIngress = errors.New("forbidden: admin key cannot be used on ingress")
)

type forbiddenAdminKeyError struct {
	keyID string
}

func (e *forbiddenAdminKeyError) Error() string {
	return ErrForbiddenAdminKeyOnIngress.Error()
}

func (e *forbiddenAdminKeyError) Unwrap() error {
	return ErrForbiddenAdminKeyOnIngress
}

func isNonAdminKey(k *auth.StoredAPIKey) bool {
	return k != nil && !auth.IsAdminRole(k.Role)
}

// ContextExtractor authenticates MCP ingress requests strictly using
// fail-closed Authorization: Bearer API keys.
type ContextExtractor struct {
	mu           sync.RWMutex
	keyValidator auth.KeyValidator
}

// NewContextExtractor initializes a ContextExtractor bound to an optional KeyValidator.
func NewContextExtractor(keyValidator ...auth.KeyValidator) *ContextExtractor {
	extractor := &ContextExtractor{}
	if len(keyValidator) > 0 && keyValidator[0] != nil {
		extractor.keyValidator = keyValidator[0]
	}
	return extractor
}

// SetKeyValidator sets or updates the KeyValidator used for client API key verification.
func (c *ContextExtractor) SetKeyValidator(v auth.KeyValidator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyValidator = v
}

// Authenticate verifies Authorization: Bearer <token> against keyValidator and returns
// a UserContext derived exclusively from the verified StoredAPIKey.
// Unauthenticated requests, non-Bearer credentials, nil keyValidator, or invalid/revoked keys
// fail closed with ErrUnauthorized; Admin keys fail with ErrForbiddenAdminKeyOnIngress.
func (c *ContextExtractor) Authenticate(r *http.Request) (*filter.UserContext, error) {
	if r == nil || c == nil {
		return nil, ErrUnauthorized
	}

	c.mu.RLock()
	kv := c.keyValidator
	c.mu.RUnlock()
	if kv == nil {
		return nil, ErrUnauthorized
	}

	clientIPStr := clientIPString(r)
	rawToken := extractBearerToken(r.Header.Get("Authorization"))
	if rawToken == "" {
		slog.WarnContext(r.Context(), "Unauthenticated ingress request rejected", slog.String("client_ip", clientIPStr))
		return nil, ErrUnauthorized
	}

	keyRecord, ok := validateKeyWithNonAdminUsage(kv, rawToken)
	if !ok || keyRecord == nil {
		slog.WarnContext(r.Context(), "Invalid or revoked API key presented", slog.String("client_ip", clientIPStr))
		return nil, ErrUnauthorized
	}

	if auth.IsAdminRole(keyRecord.Role) {
		slog.WarnContext(r.Context(), "Admin API key rejected on MCP ingress",
			slog.String("client_ip", clientIPStr),
			slog.String("key_id", keyRecord.ID),
		)
		return nil, &forbiddenAdminKeyError{keyID: keyRecord.ID}
	}

	return &filter.UserContext{
		UserID:    cmp.Or(keyRecord.Name, keyRecord.ID),
		Role:      keyRecord.Role,
		AgentName: keyRecord.AgentName,
		APIKeyID:  keyRecord.ID,
		ClientIP:  clientIPStr,
	}, nil
}

// Extract parses, verifies credentials, and returns a verified UserContext, or nil on failure.
func (c *ContextExtractor) Extract(r *http.Request) *filter.UserContext {
	uCtx, err := c.Authenticate(r)
	if err != nil {
		return nil
	}
	return uCtx
}

func extractBearerToken(authHeader string) string {
	const bearerPrefix = "Bearer "
	if len(authHeader) <= len(bearerPrefix) || !strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(bearerPrefix):])
}

func validateKeyWithNonAdminUsage(validator auth.KeyValidator, rawToken string) (*auth.StoredAPIKey, bool) {
	if singlePass, hasSinglePass := validator.(interface {
		ValidateKeyWithUsage(rawToken string, shouldRecordUsage func(*auth.StoredAPIKey) bool) (*auth.StoredAPIKey, bool)
	}); hasSinglePass {
		return singlePass.ValidateKeyWithUsage(rawToken, isNonAdminKey)
	}
	if nonMutating, hasNonMutating := validator.(interface {
		ValidateKeyWithoutUsage(rawToken string) (*auth.StoredAPIKey, bool)
	}); hasNonMutating {
		keyRecord, ok := nonMutating.ValidateKeyWithoutUsage(rawToken)
		if ok && keyRecord != nil && !auth.IsAdminRole(keyRecord.Role) {
			return validator.ValidateKey(rawToken)
		}
		return keyRecord, ok
	}
	return validator.ValidateKey(rawToken)
}

func clientIPString(r *http.Request) string {
	if ip := extractClientIP(r); ip != nil {
		return ip.String()
	}
	return ""
}

// extractClientIP extracts the remote peer IP address from http.Request.
func extractClientIP(r *http.Request) net.IP {
	if r == nil || r.RemoteAddr == "" {
		return nil
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return net.ParseIP(host)
}
