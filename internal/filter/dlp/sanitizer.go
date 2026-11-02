package dlp

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// RedactedPlaceholder is the default replacement text for masked PII/sensitive data.
const RedactedPlaceholder = "[REDACTED]"

// SanitizeResult encapsulates the outcome of DLP inspection and sanitization.
// Fields are ordered by alignment to eliminate internal struct padding.
type SanitizeResult struct {
	HITLRuleDetail *CompiledPattern
	BlockingRule   string
	HITLRule       string
	Output         string
	MaskedRules    []string
	AuditedRules   []string
	Blocked        bool
	RequiresHITL   bool
	Modified       bool
	Audited        bool
}

// canonicalizePayload generates normalized variants of input to defeat single and double
// percent-encoding evasion (RFC 3986).
// High-performance fast path: if '%' is not present in input, returns []string{input} with zero decoding overhead.
func canonicalizePayload(input string) []string {
	if strings.IndexByte(input, '%') == -1 {
		return []string{input}
	}

	targets := make([]string, 1, 4)
	targets[0] = input

	contains := func(s string) bool {
		for _, t := range targets {
			if t == s {
				return true
			}
		}
		return false
	}

	// Pass 1: PathUnescape (preserves '+' characters while decoding hex %xx)
	if p1, err := url.PathUnescape(input); err == nil && p1 != input {
		if !contains(p1) {
			targets = append(targets, p1)
		}
		// Pass 2: Double unescape
		if strings.IndexByte(p1, '%') != -1 {
			if p2, err2 := url.PathUnescape(p1); err2 == nil && p2 != p1 {
				if !contains(p2) {
					targets = append(targets, p2)
				}
			}
		}
	}

	// QueryUnescape (decodes hex %xx and normalizes '+' to space)
	if q1, err := url.QueryUnescape(input); err == nil && q1 != input {
		if !contains(q1) {
			targets = append(targets, q1)
		}
		if strings.IndexByte(q1, '%') != -1 {
			if q2, err2 := url.QueryUnescape(q1); err2 == nil && q2 != q1 {
				if !contains(q2) {
					targets = append(targets, q2)
				}
			}
		}
	}

	return targets
}

// FormatPlaceholder returns a standardized semantic placeholder for a DLP pattern.
// If custom is provided and not empty, it is used verbatim.
// If custom is empty and name is provided, it generates "[REDACTED:NORMALIZED_NAME]".
// Otherwise, it returns "[REDACTED]".
func FormatPlaceholder(name, custom string) string {
	if strings.TrimSpace(custom) != "" {
		return strings.TrimSpace(custom)
	}
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return RedactedPlaceholder
	}

	var b strings.Builder
	for _, r := range cleanName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteRune('_')
		}
	}
	norm := b.String()
	for strings.Contains(norm, "__") {
		norm = strings.ReplaceAll(norm, "__", "_")
	}
	norm = strings.Trim(norm, "_")
	if norm == "" {
		return RedactedPlaceholder
	}
	return fmt.Sprintf("[REDACTED:%s]", norm)
}

// Sanitize executes the ADR-0022, ADR-0033, and ADR-0040 multi-pass DLP algorithm against the provided input:
// Pass 1: Check all 'block' rules first (Absolute Block Precedence on collision).
// Pass 1.5: Check all 'hitl' rules (Interactive human approval before tool execution).
// Pass 2: Check all 'audit' rules (non-mutating dry-run / monitor observation).
// Pass 3: Apply in-place semantic redaction for matching 'mask' rules.
func Sanitize(input string, patterns []CompiledPattern) SanitizeResult {
	if len(patterns) == 0 || input == "" {
		return SanitizeResult{Output: input}
	}

	targets := canonicalizePayload(input)

	// Pass 1: Block rules take absolute precedence across all canonicalized variants
	for _, target := range targets {
		for _, p := range patterns {
			if p.Action == ActionBlock && p.Regex != nil && p.Regex.MatchString(target) {
				return SanitizeResult{
					Blocked:      true,
					BlockingRule: p.Name,
					Output:       input,
				}
			}
		}
	}

	// Pass 1.5: HITL rules take precedence over mask and audit across all canonicalized variants
	for _, target := range targets {
		for i := range patterns {
			p := &patterns[i]
			if p.Action == ActionHITL && p.Regex != nil && p.Regex.MatchString(target) {
				return SanitizeResult{
					RequiresHITL:   true,
					HITLRule:       p.Name,
					HITLRuleDetail: p,
					Output:         input,
				}
			}
		}
	}

	// Pass 2: Audit rules (monitor only, zero payload modification)
	var auditedRules []string
	auditedSet := make(map[string]struct{})
	for _, target := range targets {
		for _, p := range patterns {
			if p.Action == ActionAudit && p.Regex != nil && p.Regex.MatchString(target) {
				if _, seen := auditedSet[p.Name]; !seen {
					auditedSet[p.Name] = struct{}{}
					auditedRules = append(auditedRules, p.Name)
				}
			}
		}
	}
	audited := len(auditedRules) > 0

	// Pass 3: Mask sanitization with semantic placeholders
	result := input
	modified := false
	var maskedRules []string
	for _, p := range patterns {
		if p.Action != ActionBlock && p.Action != ActionHITL && p.Action != ActionAudit && p.Regex != nil && p.Regex.MatchString(result) {
			placeholder := FormatPlaceholder(p.Name, p.Placeholder)
			result = p.Regex.ReplaceAllString(result, placeholder)
			modified = true
			maskedRules = append(maskedRules, p.Name)
		}
	}

	return SanitizeResult{
		Modified:     modified,
		MaskedRules:  maskedRules,
		Audited:      audited,
		AuditedRules: auditedRules,
		Output:       result,
	}
}
