package mcpexport

import (
	"fmt"
	"regexp"
	"strings"
)

var adoptedClientSuffixRe = regexp.MustCompile(`\s+\([^)]+\)$`)

// SanitizeServerKey derives a deterministic, client-safe mcpServers key from a Tool Source's
// name or ID, stripping adopted client labels, collapsing "__" to "_", and guarding against
// FaradAiWire self-reference prefixes.
func SanitizeServerKey(name, id string) string {
	candidate := strings.TrimSpace(name)
	if candidate == "" {
		candidate = strings.TrimSpace(id)
	}
	candidate = adoptedClientSuffixRe.ReplaceAllString(candidate, "")
	candidate = strings.TrimSpace(candidate)

	var b strings.Builder
	b.Grow(len(candidate))
	lastDash := false
	for _, r := range candidate {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_':
			b.WriteRune(r)
			lastDash = false
		case r == '-':
			if !lastDash && b.Len() > 0 {
				b.WriteRune('-')
				lastDash = true
			}
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}

	sanitized := strings.Trim(b.String(), "-_")
	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}
	sanitized = strings.Trim(sanitized, "-_")
	if sanitized == "" {
		sanitized = "mcp-server"
	}

	if isSelfReferenceServerKey(sanitized) {
		sanitized = "upstream-" + sanitized
	}
	return sanitized
}

func isSelfReferenceServerKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.HasPrefix(lower, "farad-ai") ||
		strings.HasPrefix(lower, "faradai") ||
		strings.Contains(lower, "faradaiwire") ||
		strings.Contains(lower, "faradaimcp")
}

// AllocateServerKey returns a collision-free key by appending -2, -3, ... in deterministic order.
func AllocateServerKey(base string, used map[string]int) string {
	if used == nil {
		return base
	}
	if count, exists := used[base]; !exists {
		used[base] = 1
		return base
	} else {
		next := count + 1
		for {
			candidate := fmt.Sprintf("%s-%d", base, next)
			if _, clash := used[candidate]; !clash {
				used[base] = next
				used[candidate] = 1
				return candidate
			}
			next++
		}
	}
}

// SplitStdioCommand tokenizes a single-string stdio command into executable and arguments while
// preserving quoted paths containing spaces (single quotes, double quotes, and backslash escapes).
func SplitStdioCommand(raw string) (string, []string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil, nil
	}

	var tokens []string
	var cur strings.Builder
	inToken := false
	inSingle := false
	inDouble := false
	escaped := false

	for _, r := range trimmed {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
			inToken = true
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(r)
			}
			inToken = true
		case inDouble:
			if r == '\\' {
				escaped = true
			} else if r == '"' {
				inDouble = false
			} else {
				cur.WriteRune(r)
			}
			inToken = true
		default:
			switch r {
			case '\\':
				escaped = true
				inToken = true
			case '\'':
				inSingle = true
				inToken = true
			case '"':
				inDouble = true
				inToken = true
			case ' ', '\t', '\n', '\r':
				if inToken {
					tokens = append(tokens, cur.String())
					cur.Reset()
					inToken = false
				}
			default:
				cur.WriteRune(r)
				inToken = true
			}
		}
	}

	if escaped {
		return "", nil, fmt.Errorf("dangling escape in stdio command")
	}
	if inSingle || inDouble {
		return "", nil, fmt.Errorf("unterminated quote in stdio command")
	}
	if inToken {
		tokens = append(tokens, cur.String())
	}
	if len(tokens) == 0 {
		return "", nil, nil
	}
	var args []string
	if len(tokens) > 1 {
		args = tokens[1:]
	}
	return tokens[0], args, nil
}
