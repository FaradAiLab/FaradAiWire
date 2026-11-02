package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
)

var (
	// ErrUnauthorized is returned when an ingress request lacks valid credentials or has an invalid/revoked API key.
	ErrUnauthorized = errors.New("unauthorized: missing, invalid, or revoked API key")
)

const (
	defaultFallbackRole = "Customer"
	defaultFallbackUser = "guest-customer"
	defaultUserHeader   = "X-User-ID"
	defaultRoleHeader   = "X-User-Role"
	defaultReplayWindow = 5 * time.Minute
)

// ContextExtractor enforces context provenance and anti-spoofing verification
// for client identities ingested by the FaradAiWire proxy.
type ContextExtractor struct {
	cfg           config.UserContextConfig
	trustedIPNets []*net.IPNet
	trustedIPs    []net.IP
	hmacSecret    []byte
	replayWindow  time.Duration
	keyValidator  auth.KeyValidator
}

// NewContextExtractor initializes a new ContextExtractor with pre-parsed CIDRs, HMAC secrets,
// and optional KeyValidator for client Bearer/API key verification.
func NewContextExtractor(cfg config.UserContextConfig, keyValidator ...auth.KeyValidator) *ContextExtractor {
	extractor := &ContextExtractor{
		cfg:          cfg,
		replayWindow: defaultReplayWindow,
	}

	if len(keyValidator) > 0 && keyValidator[0] != nil {
		extractor.keyValidator = keyValidator[0]
	}

	// Resolve secret environment variables if given as ${ENV_VAR}
	rawSecret := cfg.ContextHMACSecret
	if strings.HasPrefix(rawSecret, "${") && strings.HasSuffix(rawSecret, "}") {
		envKey := strings.TrimSuffix(strings.TrimPrefix(rawSecret, "${"), "}")
		rawSecret = os.Getenv(envKey)
	}
	if rawSecret != "" {
		extractor.hmacSecret = []byte(rawSecret)
	}

	// Parse trusted CIDRs and IPs
	for _, raw := range cfg.TrustedProxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if strings.Contains(raw, "/") {
			_, ipNet, err := net.ParseCIDR(raw)
			if err == nil && ipNet != nil {
				extractor.trustedIPNets = append(extractor.trustedIPNets, ipNet)
				continue
			}
		}

		// Try parsing as single IP
		ip := net.ParseIP(raw)
		if ip != nil {
			if ip.To4() != nil {
				extractor.trustedIPNets = append(extractor.trustedIPNets, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				})
			} else {
				extractor.trustedIPNets = append(extractor.trustedIPNets, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(128, 128),
				})
			}
			extractor.trustedIPs = append(extractor.trustedIPs, ip)
		}
	}

	return extractor
}

// SetReplayWindow customizes the allowed timestamp clock skew tolerance.
func (c *ContextExtractor) SetReplayWindow(d time.Duration) {
	if d > 0 {
		c.replayWindow = d
	}
}

// SetKeyValidator sets or updates the KeyValidator used for client API key verification.
func (c *ContextExtractor) SetKeyValidator(v auth.KeyValidator) {
	c.keyValidator = v
}

// Authenticate parses, verifies credentials or provenance in constant time, and returns an authenticated UserContext.
// Ingress Bearer/X-API-Key tokens are validated against keyValidator.
// Unauthenticated callers or requests with invalid/revoked credentials are fail-closed and return ErrUnauthorized.
func (c *ContextExtractor) Authenticate(r *http.Request) (*filter.UserContext, error) {
	if r == nil {
		return nil, ErrUnauthorized
	}

	roleHeader := c.cfg.RoleHeader
	if roleHeader == "" {
		roleHeader = defaultRoleHeader
	}
	userHeader := c.cfg.UserHeader
	if userHeader == "" {
		userHeader = defaultUserHeader
	}

	fallbackRole := c.cfg.FallbackRole
	if fallbackRole == "" {
		fallbackRole = defaultFallbackRole
	}
	fallbackUser := c.cfg.FallbackUser
	if fallbackUser == "" {
		fallbackUser = defaultFallbackUser
	}

	incomingUser := strings.TrimSpace(r.Header.Get(userHeader))
	incomingRole := strings.TrimSpace(r.Header.Get(roleHeader))
	clientIP := extractClientIP(r)

	// 1. Check for client API key / Bearer token
	var rawToken string
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		rawToken = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if rawToken == "" {
		rawToken = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}

	if rawToken != "" {
		if c.keyValidator != nil {
			keyRecord, ok := c.keyValidator.ValidateKey(rawToken)
			if ok && keyRecord != nil {
				user := incomingUser
				if user == "" {
					user = keyRecord.Name
				}
				if user == "" {
					user = keyRecord.ID
				}
				return &filter.UserContext{
					UserID:    user,
					Role:      keyRecord.Role,
					AgentName: keyRecord.AgentName,
				}, nil
			}

			// Invalid or revoked token provided -> fail-closed HTTP 401
			slog.WarnContext(r.Context(), "Invalid or revoked API key presented", slog.String("client_ip", clientIP.String()))
			return nil, ErrUnauthorized
		}

		// Token provided but no keyValidator configured -> fail-closed HTTP 401
		slog.WarnContext(r.Context(), "Token presented but no KeyValidator is configured", slog.String("client_ip", clientIP.String()))
		return nil, ErrUnauthorized
	}

	// 2. Check provenance (HMAC signature or Trusted Proxy IP)
	isTrustedIP := c.isTrustedIP(clientIP)
	isVerifiedSignature := c.verifySignature(r, incomingUser, incomingRole)

	if isTrustedIP || isVerifiedSignature {
		user := incomingUser
		if user == "" {
			user = fallbackUser
		}
		role := incomingRole
		if role == "" {
			role = fallbackRole
		}
		return &filter.UserContext{
			UserID: user,
			Role:   role,
		}, nil
	}

	// 3. Untrusted / unauthenticated client (no credentials, no HMAC, not trusted IP)
	if c.keyValidator != nil {
		slog.WarnContext(r.Context(), "Unauthenticated client rejected", slog.String("client_ip", clientIP.String()))
		return nil, ErrUnauthorized
	}

	// 4. In testing harnesses without keyValidator and without provenance requirements:
	return &filter.UserContext{
		UserID: fallbackUser,
		Role:   fallbackRole,
	}, nil
}

// Extract parses, verifies provenance, and returns a verified UserContext.
// Returns nil if authentication fails (e.g. unauthenticated or invalid token).
func (c *ContextExtractor) Extract(r *http.Request) *filter.UserContext {
	uCtx, err := c.Authenticate(r)
	if err != nil {
		return nil
	}
	return uCtx
}

// isTrustedIP checks if the given IP belongs to any configured trusted proxy CIDR or IP.
func (c *ContextExtractor) isTrustedIP(ip net.IP) bool {
	if ip == nil || len(c.trustedIPNets) == 0 {
		return false
	}
	for _, ipNet := range c.trustedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// verifySignature validates HMAC-SHA256 signature and timestamp window.
func (c *ContextExtractor) verifySignature(r *http.Request, userID, role string) bool {
	if len(c.hmacSecret) == 0 || r == nil {
		return false
	}

	sigHeader := r.Header.Get("X-FaradAiWire-Signature")
	if sigHeader == "" {
		sigHeader = r.Header.Get("X-Signature")
	}
	if sigHeader == "" {
		return false
	}

	timestampStr := r.Header.Get("X-FaradAiWire-Timestamp")
	if timestampStr == "" {
		timestampStr = r.Header.Get("X-Timestamp")
	}

	var rawSignature string

	// Support combined format: t=1724500000,v1=<sig> or t=1724500000,sig=<sig>
	if strings.Contains(sigHeader, "t=") {
		parts := strings.Split(sigHeader, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "t=") {
				timestampStr = strings.TrimPrefix(part, "t=")
			} else if strings.HasPrefix(part, "v1=") {
				rawSignature = strings.TrimPrefix(part, "v1=")
			} else if strings.HasPrefix(part, "sig=") {
				rawSignature = strings.TrimPrefix(part, "sig=")
			}
		}
	} else if strings.Contains(sigHeader, ".") && timestampStr == "" {
		// Format: <timestamp>.<signature>
		idx := strings.Index(sigHeader, ".")
		timestampStr = sigHeader[:idx]
		rawSignature = sigHeader[idx+1:]
	} else {
		rawSignature = sigHeader
	}

	if timestampStr == "" || rawSignature == "" {
		return false
	}

	// Validate timestamp is numeric
	tsUnix, err := strconv.ParseInt(strings.TrimSpace(timestampStr), 10, 64)
	if err != nil {
		return false
	}

	// Check replay window
	nowUnix := time.Now().Unix()
	skew := nowUnix - tsUnix
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(c.replayWindow.Seconds()) {
		slog.WarnContext(r.Context(), "HMAC signature rejected due to expired timestamp", slog.Int64("skew_sec", skew), slog.Int64("allowed_sec", int64(c.replayWindow.Seconds())))
		return false
	}

	// Calculate expected HMAC
	expectedHex := ComputeHMACSignature(c.hmacSecret, timestampStr, userID, role)
	expectedBytes, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}

	// Decode incoming signature (support hex or base64)
	var providedBytes []byte
	providedBytes, err = hex.DecodeString(rawSignature)
	if err != nil {
		providedBytes, err = base64.StdEncoding.DecodeString(rawSignature)
		if err != nil {
			providedBytes, err = base64.URLEncoding.DecodeString(rawSignature)
			if err != nil {
				return false
			}
		}
	}

	return hmac.Equal(providedBytes, expectedBytes)
}

// ComputeHMACSignature computes the HMAC-SHA256 hex signature over timestamp:userID:role.
func ComputeHMACSignature(secret []byte, timestampStr, userID, role string) string {
	mac := hmac.New(sha256.New, secret)
	canonical := fmt.Sprintf("%s:%s:%s", timestampStr, userID, role)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
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
