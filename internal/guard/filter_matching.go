package guard

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

// DefaultL1Patterns returns baseline in-memory regex patterns for sub-millisecond interception.
func DefaultL1Patterns() []config.DLPPattern {
	return []config.DLPPattern{
		{
			Name:   "system_override",
			Regex:  `(?i)(ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|preceding|above)\s+(instructions|orders|prompts)|disregard\s+all\s+prior\s+prompts|system\s+instruction\s+override)`,
			Action: "block",
		},
		{
			Name:   "sensitive_files",
			Regex:  `(?i)(\.env|\.aws/credentials|/etc/shadow|/etc/passwd|id_rsa|id_ed25519)`,
			Action: "block",
		},
		{
			Name:   "api_key_redact",
			Regex:  `(?i)(bearer\s+[A-Za-z0-9\-_\.]{20,}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{40,})`,
			Action: "mask",
		},
	}
}

// DefaultFastPathPatterns returns the standard tool prefixes that qualify for Fast-Path microsecond execution.
func DefaultFastPathPatterns() []string {
	return []string{
		"read_*",
		"get_*",
		"search_*",
		"list_*",
		"query_*",
		"describe_*",
		"fetch_*",
		"view_*",
	}
}

// DefaultCriticalBlocks returns high-risk destructive tools subjected to mandatory blocking on threat flags.
func DefaultCriticalBlocks() []string {
	return []string{
		"execute_bash",
		"execute_command",
		"run_command",
		"exec_*",
		"*exec*",
		"drop_db",
		"delete_database",
		"format_disk",
	}
}

// ShouldPromoteToL2 evaluates if a Fast-Path tool call exhibits natural language characteristics.
// It elevates calls when payload character length > maxChars AND word count > minWords.
func ShouldPromoteToL2(payload string, maxChars int, minWords int) bool {
	if maxChars <= 0 {
		maxChars = 128
	}
	if minWords <= 0 {
		minWords = 5
	}
	if len(payload) <= maxChars {
		return false
	}
	words := strings.Fields(payload)
	return len(words) > minWords
}

// ExtractArgumentsText extracts all string values or serialized JSON from tool arguments.
func ExtractArgumentsText(args map[string]interface{}, rawParams json.RawMessage) string {
	if len(args) == 0 {
		return string(rawParams)
	}
	var sb strings.Builder
	for _, v := range args {
		switch val := v.(type) {
		case string:
			if sb.Len() > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(val)
		default:
			b, err := json.Marshal(val)
			if err == nil {
				if sb.Len() > 0 {
					sb.WriteString(" ")
				}
				sb.Write(b)
			}
		}
	}
	if sb.Len() == 0 {
		return string(rawParams)
	}
	return sb.String()
}

func stripProtocolPrefix(toolName string) string {
	if idx := strings.Index(toolName, "__"); idx >= 0 {
		return toolName[idx+2:]
	}
	return toolName
}

func (f *GuardFilter) isFastPath(toolName string, patterns []string) bool {
	toolLower := strings.ToLower(toolName)
	stripped := strings.ToLower(stripProtocolPrefix(toolName))
	for _, p := range patterns {
		pLower := strings.ToLower(p)
		if matched, _ := path.Match(pLower, toolLower); matched {
			return true
		}
		if stripped != toolLower {
			if matched, _ := path.Match(pLower, stripped); matched {
				return true
			}
		}
	}
	return false
}

func (f *GuardFilter) isCriticalBlock(toolName string, criticalBlocks []string) bool {
	toolLower := strings.ToLower(toolName)
	stripped := strings.ToLower(stripProtocolPrefix(toolName))

	matches := func(pattern string) bool {
		pLower := strings.ToLower(pattern)
		if strings.EqualFold(pLower, toolLower) || strings.EqualFold(pLower, stripped) {
			return true
		}
		if matched, _ := path.Match(pLower, toolLower); matched {
			return true
		}
		if stripped != toolLower {
			if matched, _ := path.Match(pLower, stripped); matched {
				return true
			}
		}
		return false
	}

	for _, cb := range criticalBlocks {
		if matches(cb) {
			return true
		}
	}

	f.mu.RLock()
	cat := f.catalog
	f.mu.RUnlock()

	if cat != nil {
		if activeModel, err := cat.GetActive(context.Background()); err == nil && activeModel != nil {
			for _, ct := range activeModel.GetCriticalTools() {
				if matches(ct) {
					return true
				}
			}
		}
	}

	return false
}

func (f *GuardFilter) isDefaultActionBlock() bool {
	f.mu.RLock()
	cat := f.catalog
	f.mu.RUnlock()

	if cat == nil {
		return false
	}

	activeModel, err := cat.GetActive(context.Background())
	if err != nil || activeModel == nil {
		return false
	}

	return activeModel.DefaultAction == ThreatActionBlock
}

func (f *GuardFilter) isExternalEgress(toolName string) bool {
	toolLower := strings.ToLower(toolName)
	externalKeywords := []string{
		"search", "tavily", "brave", "google", "web", "fetch", "http",
		"curl", "browser", "scrape", "slack", "mail", "smtp", "webhook",
		"external", "download", "upload", "rest", "api",
	}
	for _, kw := range externalKeywords {
		if strings.Contains(toolLower, kw) {
			return true
		}
	}
	return false
}

