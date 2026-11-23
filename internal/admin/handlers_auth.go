package admin

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
)

const (
	adminSessionCookieName = "faw_admin_session"
	adminSessionTTL        = 24 * time.Hour
	maxTrackedLoginIPs     = 2048
)

// AdminSessionRequest is the JSON payload for POST /admin/auth/session.
// Accepts both "api_key" (canonical API contract) and "token" (Web UI login form).
type AdminSessionRequest struct {
	APIKey string `json:"api_key"`
	Token  string `json:"token"`
}

type loginAttemptState struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

type adminLoginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttemptState
}

func newAdminLoginLimiter() *adminLoginLimiter {
	return &adminLoginLimiter{
		attempts: make(map[string]*loginAttemptState),
	}
}

func (l *adminLoginLimiter) isLocked(ip string, now time.Time) bool {
	if l == nil || ip == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.attempts[ip]
	if !ok || st == nil {
		return false
	}
	if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
		return true
	}
	if !st.lockedUntil.IsZero() && !now.Before(st.lockedUntil) {
		delete(l.attempts, ip)
	}
	return false
}

func (l *adminLoginLimiter) recordFailure(ip string, now time.Time, maxAttempts int, lockoutSec int) {
	if l == nil || ip == "" {
		return
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockoutSec <= 0 {
		lockoutSec = 900
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.attempts) >= maxTrackedLoginIPs {
		for k, v := range l.attempts {
			if v == nil || now.Sub(v.lastSeen) > time.Hour {
				delete(l.attempts, k)
			}
		}
		if len(l.attempts) >= maxTrackedLoginIPs {
			l.attempts = make(map[string]*loginAttemptState)
		}
	}
	st, ok := l.attempts[ip]
	if !ok || st == nil {
		st = &loginAttemptState{}
		l.attempts[ip] = st
	}
	st.failures++
	st.lastSeen = now
	if st.failures >= maxAttempts {
		st.lockedUntil = now.Add(time.Duration(lockoutSec) * time.Second)
	}
}

func (l *adminLoginLimiter) reset(ip string) {
	if l == nil || ip == "" {
		return
	}
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}

func (a *AdminServer) isAdminAuthRequired() bool {
	if resolveConfiguredAdminToken() != "" {
		return true
	}
	cfg := a.Config()
	if cfg == nil {
		return false
	}
	return !isLoopbackHost(cfg.GetAdminHost())
}

func (a *AdminServer) hasActiveAdminCredential() bool {
	if resolveConfiguredAdminToken() != "" {
		return true
	}
	if a.keyStore == nil {
		return false
	}
	for _, k := range a.keyStore.ListKeys() {
		if k != nil && !k.Revoked && strings.EqualFold(k.Role, "Admin") {
			return true
		}
	}
	return false
}

func (a *AdminServer) validateAdminStartCredentials(adminHost string) error {
	if !isLoopbackHost(adminHost) && !a.hasActiveAdminCredential() {
		return &adminStartCredentialError{adminHost: adminHost}
	}
	return nil
}

type adminStartCredentialError struct {
	adminHost string
}

func (e *adminStartCredentialError) Error() string {
	return "refusing to bind Admin Server to non-loopback host \"" + e.adminHost + "\" without ADMIN_API_KEY, FARADAI_WIRE_ADMIN_TOKEN, or an active Admin key in KeyStore configured"
}

// validateAdminCredential verifies an incoming bearer or login credential and returns validity, Admin role membership, and verified actor ID.
func (a *AdminServer) validateAdminCredential(rawToken string) (valid bool, isAdmin bool, actorID string) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return false, false, ""
	}
	if expected := resolveConfiguredAdminToken(); expected != "" {
		providedHash := sha256.Sum256([]byte(rawToken))
		expectedHash := sha256.Sum256([]byte(expected))
		if subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1 {
			return true, true, "env:admin_token"
		}
	}
	if a.keyStore != nil {
		if rec, ok := a.keyStore.ValidateKey(rawToken); ok && rec != nil && !rec.Revoked {
			return true, strings.EqualFold(rec.Role, "Admin"), rec.ID
		}
	}
	return false, false, ""
}

func (a *AdminServer) deriveAdminSessionSecrets() [][]byte {
	var secrets [][]byte
	if expected := resolveConfiguredAdminToken(); expected != "" {
		sum := sha256.Sum256([]byte("faw-admin-session-env:" + expected))
		secrets = append(secrets, sum[:])
	}
	if a.keyStore != nil {
		if provider, ok := a.keyStore.(interface{ ActiveAdminCredentials() []*auth.StoredAPIKey }); ok {
			for _, rec := range provider.ActiveAdminCredentials() {
				if rec != nil && !rec.Revoked && strings.EqualFold(rec.Role, "Admin") {
					sum := sha256.Sum256([]byte("faw-admin-session-key:" + rec.ID + ":" + rec.Salt + ":" + rec.Hash))
					secrets = append(secrets, sum[:])
				}
			}
		} else {
			for _, meta := range a.keyStore.ListKeys() {
				if meta != nil && !meta.Revoked && strings.EqualFold(meta.Role, "Admin") && meta.RawKey != "" {
					sum := sha256.Sum256([]byte("faw-admin-session-mem:" + meta.ID + ":" + meta.RawKey))
					secrets = append(secrets, sum[:])
				}
			}
		}
	}
	return secrets
}

func (a *AdminServer) signAdminSessionCookieValue(actorID string) (string, bool) {
	secrets := a.deriveAdminSessionSecrets()
	if len(secrets) == 0 {
		return "", false
	}
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		actorID = "env:admin_token"
	}
	expHex := strconv.FormatInt(time.Now().Add(adminSessionTTL).Unix(), 16)
	payload := expHex + "." + actorID
	mac := hmac.New(sha256.New, secrets[0])
	_, _ = mac.Write([]byte(payload))
	sigHex := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sigHex, true
}

func (a *AdminServer) extractValidAdminSessionCookie(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil {
		return "", false
	}
	raw := strings.TrimSpace(cookie.Value)
	if raw == "" {
		return "", false
	}
	firstDot := strings.IndexByte(raw, '.')
	lastDot := strings.LastIndexByte(raw, '.')
	if firstDot <= 0 || lastDot <= 0 || lastDot >= len(raw)-1 {
		return "", false
	}
	expHex := raw[:firstDot]
	sigHex := raw[lastDot+1:]
	if sigHex == "" {
		return "", false
	}
	expUnix, parseErr := strconv.ParseInt(expHex, 16, 64)
	if parseErr != nil || expUnix <= time.Now().Unix() {
		return "", false
	}
	sigBytes, hexErr := hex.DecodeString(sigHex)
	if hexErr != nil || len(sigBytes) != sha256.Size {
		return "", false
	}

	var payload, actorID string
	if firstDot == lastDot {
		// Backward-compatible legacy 2-part cookie: expHex.sigHex
		payload = expHex
		actorID = "legacy:session"
	} else {
		actorID = raw[firstDot+1 : lastDot]
		if actorID == "" {
			return "", false
		}
		payload = raw[:lastDot]
	}

	for _, secret := range a.deriveAdminSessionSecrets() {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(payload))
		if hmac.Equal(sigBytes, mac.Sum(nil)) {
			return actorID, true
		}
	}
	return "", false
}

func (a *AdminServer) isValidAdminSessionCookie(r *http.Request) bool {
	_, ok := a.extractValidAdminSessionCookie(r)
	return ok
}

func isHTTPSRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func setAdminSessionCookie(w http.ResponseWriter, r *http.Request, val string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    val,
		Path:     "/",
		MaxAge:   int(adminSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPSRequest(r),
	})
}

func clearAdminSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPSRequest(r),
	})
}

func clientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (a *AdminServer) authenticateAndSetSessionCookie(w http.ResponseWriter, r *http.Request, rawCredential, flow string, jsonUnauthorized bool) bool {
	clientIP := clientIPFromRequest(r)
	now := time.Now()
	if a.loginLimiter != nil && a.loginLimiter.isLocked(clientIP, now) {
		slog.WarnContext(r.Context(), "Admin login blocked by rate limiter lockout",
			slog.String("flow", flow),
			slog.String("client_ip", clientIP),
			slog.String("reason", "TOO_MANY_ATTEMPTS"),
		)
		a.logSecurityAuditAs(r, "anonymous", "unknown", "admin_auth_lockout", flow, "admin_auth", r.URL.Path, "locked", "too_many_failed_attempts", nil)
		writeError(w, http.StatusTooManyRequests, "TOO_MANY_ATTEMPTS", "Too many failed authentication attempts; try again later")
		return false
	}

	valid, isAdmin, actorID := a.validateAdminCredential(rawCredential)
	if !valid {
		rlCfg := a.Config().GetHTTPRateLimitConfig()
		if a.loginLimiter != nil {
			a.loginLimiter.recordFailure(clientIP, now, rlCfg.LoginMaxAttempts, rlCfg.LoginLockoutSec)
		}
		slog.WarnContext(r.Context(), "Rejected invalid Admin Console credential",
			slog.String("flow", flow),
			slog.String("client_ip", clientIP),
			slog.String("reason", "INVALID_CREDENTIALS"),
		)
		a.logSecurityAuditAs(r, "anonymous", "unknown", "admin_auth_failed", flow, "admin_auth", r.URL.Path, "denied", "invalid_credentials", nil)
		if jsonUnauthorized {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid API key")
		} else {
			http.Error(w, "Unauthorized: invalid bootstrap token", http.StatusUnauthorized)
		}
		return false
	}
	if !isAdmin {
		slog.WarnContext(r.Context(), "Rejected non-Admin API key on Admin login",
			slog.String("flow", flow),
			slog.String("client_ip", clientIP),
			slog.String("reason", "ADMIN_ROLE_REQUIRED"),
		)
		a.logSecurityAuditAs(r, actorID, "non_admin", "admin_auth_forbidden", flow, "admin_auth", r.URL.Path, "denied", "admin_role_required", nil)
		writeError(w, http.StatusForbidden, "ADMIN_ROLE_REQUIRED", "Forbidden: admin role required; scoped agent keys are restricted to ingress")
		return false
	}

	if a.loginLimiter != nil {
		a.loginLimiter.reset(clientIP)
	}
	cookieVal, ok := a.signAdminSessionCookieValue(actorID)
	if !ok {
		writeError(w, http.StatusInternalServerError, "SESSION_SIGN_FAILED", "Failed to initialize admin session")
		return false
	}
	setAdminSessionCookie(w, r, cookieVal)
	a.logSecurityAuditAs(r, actorID, "admin", "admin_auth_success", flow, "admin_auth", r.URL.Path, "allowed", "session_established", nil)
	return true
}

// handleAdminSessionCreate exchanges a valid Admin API key for an HttpOnly session cookie (POST /admin/auth/session).
func (a *AdminServer) handleAdminSessionCreate(w http.ResponseWriter, r *http.Request) {
	var req AdminSessionRequest
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	rawCredential := cmp.Or(strings.TrimSpace(req.APIKey), strings.TrimSpace(req.Token))
	if !a.authenticateAndSetSessionCookie(w, r, rawCredential, "session_api", true) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "authenticated",
		"authenticated": true,
	})
}

// handleAdminSessionLogout clears the active Admin session cookie (POST /admin/auth/logout).
func (a *AdminServer) handleAdminSessionLogout(w http.ResponseWriter, r *http.Request) {
	actorID := "anonymous"
	if id, ok := a.extractValidAdminSessionCookie(r); ok && id != "" {
		actorID = id
	} else if !a.isAdminAuthRequired() {
		actorID = "local-operator"
	}
	a.logSecurityAuditAs(r, actorID, "admin", "admin_auth_logout", "logout", "admin_auth", r.URL.Path, "allowed", "session_cleared", nil)
	clearAdminSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "logged_out",
		"authenticated": false,
	})
}

func isExactSameHostOrigin(origin string, reqHost string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	reqHostname, reqPort, err := net.SplitHostPort(reqHost)
	if err != nil {
		reqHostname = reqHost
	}
	return strings.EqualFold(strings.TrimSpace(reqHostname), strings.TrimSpace(u.Hostname())) && reqPort == u.Port()
}
