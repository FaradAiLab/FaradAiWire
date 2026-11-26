package mcpexport

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/session"
)

var (
	// Matches ${env:VAR}, ${VAR}, or ${VAR:-default}. Intentionally leaves Cursor workspace tokens untouched.
	envRefRe      = regexp.MustCompile(`\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}`)
	uriUserInfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s/@"'` + "`" + `]+)@`)
)

var cursorWorkspaceTokens = map[string]bool{
	"workspaceFolder":         true,
	"workspaceFolderBasename": true,
	"userHome":                true,
	"pathSeparator":           true,
}

var secretKeySubstrings = []string{
	"KEY",
	"TOKEN",
	"SECRET",
	"PASS",
	"PWD",
	"AUTH",
	"CREDENTIAL",
	"PRIVATE",
	"CERT",
	"SIGNATURE",
	"DSN",
	"DATABASE_URL",
	"POSTGRES_URL",
	"REDIS_URL",
	"MONGO_URI",
	"CONNECTION_STRING",
	"API",
	"PAT",
	"BEARER",
}

var secretQueryParams = map[string]bool{
	"api_key":       true,
	"apikey":        true,
	"token":         true,
	"access_token":  true,
	"secret":        true,
	"auth":          true,
	"key":           true,
	"password":      true,
	"client_secret": true,
	"sig":           true,
}

var secretFlagNames = map[string]bool{
	"token":         true,
	"api-key":       true,
	"apikey":        true,
	"api_key":       true,
	"secret":        true,
	"password":      true,
	"pass":          true,
	"auth":          true,
	"key":           true,
	"bearer":        true,
	"dsn":           true,
	"credential":    true,
	"client-secret": true,
	"client_secret": true,
}

func formatPlaceholder(name string) string {
	trimmed := strings.TrimSpace(name)
	var b strings.Builder
	b.Grow(len(trimmed) + 2)
	lastUnderscore := false
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
			lastUnderscore = false
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if b.Len() > 0 && !lastUnderscore {
				b.WriteRune('_')
				lastUnderscore = true
			}
		}
	}
	clean := strings.Trim(b.String(), "_")
	if clean == "" {
		clean = "API_KEY"
	}
	return "[" + clean + "]"
}

func isSecretKeyName(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return false
	}
	if upper == "COOKIE" || upper == "SET-COOKIE" || upper == "SET_COOKIE" {
		return true
	}
	for _, sub := range secretKeySubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}

func isOnlyEnvRefs(val string) bool {
	if !envRefRe.MatchString(val) {
		return false
	}
	return strings.TrimSpace(envRefRe.ReplaceAllString(val, "")) == ""
}

func containsURICredentials(val string) bool {
	return uriUserInfoRe.MatchString(val)
}

func redactMixedURICredentials(val string) string {
	return uriUserInfoRe.ReplaceAllStringFunc(val, func(match string) string {
		schemeIdx := strings.Index(match, "://")
		if schemeIdx < 0 || !strings.HasSuffix(match, "@") {
			return match
		}
		schemePrefix := match[:schemeIdx+3]
		userInfo := match[schemeIdx+3 : len(match)-1]
		// Preserve userinfo if it is strictly composed of env var references (and optional ':' separator).
		if strings.Trim(envRefRe.ReplaceAllString(userInfo, ""), ": ") == "" && envRefRe.MatchString(userInfo) {
			return match
		}
		return schemePrefix + "[USERNAME]:[PASSWORD]@"
	})
}

// normalizeEnvRefs converts ${VAR}, ${env:VAR}, and ${VAR:-default} references according to Target Client syntax
// without ever performing server-side os.ExpandEnv or double-wrapping ${env:env:VAR}.
func normalizeEnvRefs(val, client, serverKey string) (out string, warnings []Warning, hasEnvRef bool) {
	if !strings.Contains(val, "${") {
		return val, nil, false
	}

	matches := envRefRe.FindAllStringSubmatchIndex(val, -1)
	if len(matches) == 0 {
		return val, nil, false
	}

	var defaultStripped bool
	var unsupportedWarn bool
	var clineWarn bool

	var b strings.Builder
	b.Grow(len(val))
	lastIdx := 0

	for _, m := range matches {
		b.WriteString(val[lastIdx:m[0]])
		lastIdx = m[1]

		match := val[m[0]:m[1]]
		inner := val[m[0]+2 : m[1]-1]
		if cursorWorkspaceTokens[inner] && (client == ClientCursor || client == ClientCursorWorkspace) {
			b.WriteString(match)
			continue
		}

		varName := val[m[2]:m[3]]
		if m[4] >= 0 && m[5] > m[4] {
			defaultStripped = true
		}
		hasEnvRef = true

		switch client {
		case ClientClaudeCode:
			b.WriteString("${")
			b.WriteString(varName)
			b.WriteByte('}')
		case ClientCursor, ClientCursorWorkspace, ClientWindsurf, ClientRooCode:
			b.WriteString("${env:")
			b.WriteString(varName)
			b.WriteByte('}')
		case ClientCline:
			clineWarn = true
			b.WriteString("${env:")
			b.WriteString(varName)
			b.WriteByte('}')
		case ClientClaudeDesktop, ClientAntigravity:
			unsupportedWarn = true
			b.WriteString(formatPlaceholder(varName))
		default: // generic
			b.WriteString(formatPlaceholder(varName))
		}
	}
	b.WriteString(val[lastIdx:])

	if defaultStripped {
		warnings = append(warnings, Warning{
			Code:     WarnEnvDefaultStripped,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  "Stripped default fallback clause from ${VAR:-default} reference to prevent credential leakage.",
		})
	}
	if unsupportedWarn {
		warnings = append(warnings, Warning{
			Code:     WarnEnvInterpolationUnsupported,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  fmt.Sprintf("%s does not support environment variable interpolation; converted ${VAR} reference to placeholder.", client),
		})
	}
	if clineWarn {
		warnings = append(warnings, Warning{
			Code:     WarnClineEnvOverwriteRisk,
			Severity: SeverityInfo,
			Server:   serverKey,
			Message:  "Cline may expand ${env:VAR} placeholders into literals if the server is toggled in the Cline UI.",
		})
	}
	return b.String(), warnings, hasEnvRef
}

// RedactEnv converts ProtocolConfig.Env ("KEY=VALUE") entries into a redacted map[string]string.
func RedactEnv(entries []string, client, serverKey string) (map[string]string, []Warning) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]string)
	var warnings []Warning

	for _, entry := range entries {
		idx := strings.IndexByte(entry, '=')
		if idx <= 0 {
			warnings = append(warnings, Warning{
				Code:     WarnMalformedEnvEntry,
				Severity: SeverityWarning,
				Server:   serverKey,
				Message:  "Skipped malformed environment entry lacking 'KEY=VALUE' format.",
			})
			continue
		}
		key := strings.TrimSpace(entry[:idx])
		if key == "" {
			warnings = append(warnings, Warning{
				Code:     WarnMalformedEnvEntry,
				Severity: SeverityWarning,
				Server:   serverKey,
				Message:  "Skipped environment entry with empty key name.",
			})
			continue
		}
		val := entry[idx+1:]

		normVal, normWarns, hasEnvRef := normalizeEnvRefs(val, client, serverKey)
		warnings = append(warnings, normWarns...)

		if hasEnvRef {
			if containsURICredentials(normVal) {
				normVal = redactMixedURICredentials(normVal)
			}
			if isSecretKeyName(key) && !isOnlyEnvRefs(val) && !containsURICredentials(val) {
				out[key] = formatPlaceholder(key)
				continue
			}
			out[key] = normVal
			continue
		}
		if containsURICredentials(val) {
			out[key] = formatPlaceholder(key)
			continue
		}
		if isSecretKeyName(key) {
			// Always emit a non-empty placeholder to avoid Antigravity's "" env-clearing trap.
			out[key] = formatPlaceholder(key)
			continue
		}
		out[key] = normVal
	}

	if len(out) == 0 {
		return nil, warnings
	}
	return out, warnings
}

// RedactHeaders deduplicates headers case-insensitively, drops gateway-internal/hop-by-hop headers,
// preserves custom Headers precedence over AuthToken, and redacts all secret headers dynamically.
func RedactHeaders(serverKey, authToken string, rawHeaders map[string]string, client string) (map[string]string, []Warning) {
	var warnings []Warning

	keys := make([]string, 0, len(rawHeaders))
	for k := range rawHeaders {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	type headerEntry struct {
		canonicalKey string
		value        string
	}
	deduped := make(map[string]headerEntry)

	for _, rawKey := range keys {
		trimmedKey := strings.TrimSpace(rawKey)
		if trimmedKey == "" || session.IsBlockedUpstreamHeader(trimmedKey) {
			continue
		}
		lower := strings.ToLower(trimmedKey)
		deduped[lower] = headerEntry{
			canonicalKey: trimmedKey,
			value:        rawHeaders[rawKey],
		}
	}

	out := make(map[string]string)
	hasAuthHeader := false

	lowerKeys := make([]string, 0, len(deduped))
	for lk := range deduped {
		lowerKeys = append(lowerKeys, lk)
	}
	slices.Sort(lowerKeys)

	for _, lk := range lowerKeys {
		entry := deduped[lk]
		if lk == "authorization" {
			hasAuthHeader = true
			// Respect explicit empty Authorization header (matches session.SanitizeUpstreamHeadersWithCustom).
			if strings.TrimSpace(entry.value) == "" {
				out[entry.canonicalKey] = ""
				continue
			}
			redactedVal, w := redactAuthHeaderValue(entry.value, serverKey, client)
			warnings = append(warnings, w...)
			out[entry.canonicalKey] = redactedVal
			continue
		}

		normVal, normWarns, hasEnvRef := normalizeEnvRefs(entry.value, client, serverKey)
		warnings = append(warnings, normWarns...)
		if hasEnvRef {
			if containsURICredentials(normVal) {
				normVal = redactMixedURICredentials(normVal)
			}
			if isSecretKeyName(entry.canonicalKey) && !isOnlyEnvRefs(entry.value) && !containsURICredentials(entry.value) {
				out[entry.canonicalKey] = formatPlaceholder(entry.canonicalKey)
				continue
			}
			out[entry.canonicalKey] = normVal
			continue
		}
		if isSecretKeyName(entry.canonicalKey) || containsURICredentials(entry.value) {
			out[entry.canonicalKey] = formatPlaceholder(entry.canonicalKey)
			continue
		}
		out[entry.canonicalKey] = normVal
	}

	trimmedToken := strings.TrimSpace(authToken)
	if !hasAuthHeader && trimmedToken != "" {
		redactedVal, w := redactAuthHeaderValue(trimmedToken, serverKey, client)
		warnings = append(warnings, w...)
		out["Authorization"] = redactedVal
	}

	if len(out) == 0 {
		return nil, warnings
	}
	return out, warnings
}

func redactAuthHeaderValue(rawVal, serverKey, client string) (string, []Warning) {
	trimmed := strings.TrimSpace(rawVal)
	isBearer := len(trimmed) >= 7 && strings.EqualFold(trimmed[:7], "bearer ")

	normVal, normWarns, hasEnvRef := normalizeEnvRefs(trimmed, client, serverKey)
	if hasEnvRef {
		if isBearer {
			if isOnlyEnvRefs(trimmed[7:]) {
				return "Bearer " + strings.TrimSpace(normVal[7:]), normWarns
			}
			return "Bearer " + formatPlaceholder(serverKey+"_API_KEY"), normWarns
		}
		if isOnlyEnvRefs(trimmed) {
			return "Bearer " + normVal, normWarns
		}
		if _, rest, hasSpace := strings.Cut(trimmed, " "); hasSpace {
			if isOnlyEnvRefs(rest) {
				return normVal, normWarns
			}
			return "[AUTHORIZATION]", normWarns
		}
		return "Bearer " + formatPlaceholder(serverKey+"_API_KEY"), normWarns
	}

	if isBearer || !strings.Contains(trimmed, " ") {
		return "Bearer " + formatPlaceholder(serverKey+"_API_KEY"), normWarns
	}
	return "[AUTHORIZATION]", normWarns
}

func isSecretQueryParam(decodedKey string) bool {
	lower := strings.ToLower(strings.TrimSpace(decodedKey))
	return secretQueryParams[lower] || isSecretKeyName(decodedKey)
}

func redactKeyValueSegment(rawSegment, client, serverKey string) (string, []Warning) {
	parts := strings.Split(rawSegment, "&")
	redactedParts := make([]string, 0, len(parts))
	var warnings []Warning

	for _, part := range parts {
		if part == "" {
			continue
		}
		eqIdx := strings.IndexByte(part, '=')
		if eqIdx < 0 {
			redactedParts = append(redactedParts, part)
			continue
		}
		rawKey := part[:eqIdx]
		rawVal := part[eqIdx+1:]
		decodedKey, decErr := url.QueryUnescape(rawKey)
		if decErr != nil {
			decodedKey = rawKey
		}
		decodedVal, valErr := url.QueryUnescape(rawVal)
		if valErr != nil {
			decodedVal = rawVal
		}

		normVal, normWarns, hasEnvRef := normalizeEnvRefs(decodedVal, client, serverKey)
		warnings = append(warnings, normWarns...)
		secretParam := isSecretQueryParam(decodedKey)
		if hasEnvRef {
			if secretParam && !isOnlyEnvRefs(decodedVal) {
				redactedParts = append(redactedParts, rawKey+"="+formatPlaceholder(decodedKey))
				continue
			}
			redactedParts = append(redactedParts, rawKey+"="+normVal)
			continue
		}
		if secretParam {
			redactedParts = append(redactedParts, rawKey+"="+formatPlaceholder(decodedKey))
			continue
		}
		redactedParts = append(redactedParts, rawKey+"="+rawVal)
	}
	return strings.Join(redactedParts, "&"), warnings
}

// RedactURL scrubs embedded userinfo credentials, secret query parameters, and sensitive URL fragments
// without percent-encoding placeholders.
func RedactURL(rawURL, client, serverKey string) (string, []Warning) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", nil
	}
	var warnings []Warning

	parsed, err := url.Parse(trimmed)
	if err != nil {
		norm, w, _ := normalizeEnvRefs(trimmed, client, serverKey)
		warnings = append(warnings, w...)
		if containsURICredentials(norm) {
			norm = redactMixedURICredentials(norm)
		}
		return norm, warnings
	}

	var b strings.Builder
	if parsed.Scheme != "" {
		b.WriteString(parsed.Scheme)
		b.WriteString("://")
	}
	if parsed.User != nil {
		b.WriteString("[USERNAME]:[PASSWORD]@")
	}
	b.WriteString(parsed.Host)
	b.WriteString(parsed.EscapedPath())

	if parsed.RawQuery != "" {
		redQuery, qWarns := redactKeyValueSegment(parsed.RawQuery, client, serverKey)
		warnings = append(warnings, qWarns...)
		if redQuery != "" {
			b.WriteByte('?')
			b.WriteString(redQuery)
		}
	}

	if parsed.Fragment != "" {
		b.WriteByte('#')
		if strings.Contains(parsed.Fragment, "=") {
			redFrag, fWarns := redactKeyValueSegment(parsed.Fragment, client, serverKey)
			warnings = append(warnings, fWarns...)
			b.WriteString(redFrag)
		} else {
			normFrag, fWarns, _ := normalizeEnvRefs(parsed.Fragment, client, serverKey)
			warnings = append(warnings, fWarns...)
			if containsURICredentials(normFrag) {
				normFrag = redactMixedURICredentials(normFrag)
			}
			b.WriteString(normFrag)
		}
	}
	return b.String(), warnings
}

func redactHeaderArgValue(rawHeader, client, serverKey string) (string, []Warning) {
	name, val, hasColon := strings.Cut(rawHeader, ":")
	if !hasColon {
		normVal, normWarns, hasEnvRef := normalizeEnvRefs(rawHeader, client, serverKey)
		if hasEnvRef && isOnlyEnvRefs(rawHeader) {
			return normVal, normWarns
		}
		return formatPlaceholder("HEADER"), normWarns
	}

	trimmedName := strings.TrimSpace(name)
	trimmedVal := strings.TrimSpace(val)
	if trimmedName == "" {
		return formatPlaceholder("HEADER"), nil
	}
	if trimmedVal == "" {
		return trimmedName + ":", nil
	}
	if strings.EqualFold(trimmedName, "authorization") {
		redVal, w := redactAuthHeaderValue(trimmedVal, serverKey, client)
		return trimmedName + ": " + redVal, w
	}

	normVal, normWarns, hasEnvRef := normalizeEnvRefs(trimmedVal, client, serverKey)
	if hasEnvRef {
		if containsURICredentials(normVal) {
			normVal = redactMixedURICredentials(normVal)
		}
		if isSecretKeyName(trimmedName) && !isOnlyEnvRefs(trimmedVal) && !containsURICredentials(trimmedVal) {
			return trimmedName + ": " + formatPlaceholder(trimmedName), normWarns
		}
		return trimmedName + ": " + normVal, normWarns
	}
	if isSecretKeyName(trimmedName) || containsURICredentials(trimmedVal) {
		return trimmedName + ": " + formatPlaceholder(trimmedName), normWarns
	}
	return trimmedName + ": " + normVal, normWarns
}

// RedactArgs scrubs secrets from split stdio CLI arguments (--flag=val, --flag val, --header/-H, and embedded URIs).
func RedactArgs(args []string, client, serverKey string) ([]string, []Warning) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]string, len(args))
	var warnings []Warning
	redactNextKind := ""
	redactNextFlag := ""

	for i, arg := range args {
		if redactNextKind == "header" {
			redVal, w := redactHeaderArgValue(arg, client, serverKey)
			warnings = append(warnings, w...)
			out[i] = redVal
			redactNextKind = ""
			redactNextFlag = ""
			continue
		}
		if redactNextKind == "secret" {
			normVal, normWarns, hasEnvRef := normalizeEnvRefs(arg, client, serverKey)
			warnings = append(warnings, normWarns...)
			if hasEnvRef && isOnlyEnvRefs(arg) {
				out[i] = normVal
			} else if hasEnvRef && containsURICredentials(normVal) {
				out[i] = redactMixedURICredentials(normVal)
			} else if hasEnvRef {
				out[i] = formatPlaceholder(redactNextFlag)
			} else {
				out[i] = formatPlaceholder(redactNextFlag)
			}
			redactNextKind = ""
			redactNextFlag = ""
			continue
		}

		if strings.HasPrefix(arg, "-") {
			stripped := strings.TrimLeft(arg, "-")
			if eqIdx := strings.IndexByte(stripped, '='); eqIdx > 0 {
				rawFlag := stripped[:eqIdx]
				flagName := strings.ToLower(rawFlag)
				flagPrefix := arg[:len(arg)-len(stripped)+eqIdx+1]
				val := stripped[eqIdx+1:]
				if flagName == "header" || (arg == "-H="+val && rawFlag == "H") {
					redVal, w := redactHeaderArgValue(val, client, serverKey)
					warnings = append(warnings, w...)
					out[i] = flagPrefix + redVal
					continue
				}
				if secretFlagNames[flagName] || isSecretKeyName(flagName) {
					normVal, normWarns, hasEnvRef := normalizeEnvRefs(val, client, serverKey)
					warnings = append(warnings, normWarns...)
					if hasEnvRef && isOnlyEnvRefs(val) {
						out[i] = flagPrefix + normVal
					} else if hasEnvRef && containsURICredentials(normVal) {
						out[i] = flagPrefix + redactMixedURICredentials(normVal)
					} else {
						out[i] = flagPrefix + formatPlaceholder(flagName)
					}
					continue
				}
			} else {
				flagName := strings.ToLower(stripped)
				if flagName == "header" || arg == "-H" {
					out[i] = arg
					redactNextKind = "header"
					redactNextFlag = flagName
					continue
				}
				if secretFlagNames[flagName] || isSecretKeyName(flagName) {
					out[i] = arg
					redactNextKind = "secret"
					redactNextFlag = flagName
					continue
				}
			}
		}

		norm, normWarns, _ := normalizeEnvRefs(arg, client, serverKey)
		warnings = append(warnings, normWarns...)
		if containsURICredentials(norm) {
			norm = redactMixedURICredentials(norm)
		}
		out[i] = norm
	}

	return out, warnings
}
