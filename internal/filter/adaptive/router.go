package adaptive

import (
	"path"
	"strings"
	"sync"
)

// PathType defines whether a tool undergoes fast in-memory validation or full deep inspection.
type PathType string

const (
	PathFast PathType = "FAST_PATH"
	PathDeep PathType = "DEEP_PATH"
)

// FastPathFilterNames lists filter names that are executed in the Fast-Path pipeline.
// In-memory regex DLP executes here to protect sensitive tool responses without SLM overhead (DEC-05 / SEC-017).
var FastPathFilterNames = map[string]bool{
	"prefill_block":     true,
	"rate_limiting":     true,
	"loop_protection":   true,
	"schema_validation": true,
	"dlp":               true,
	"guard":             true,
}

// patternMatcher partitions patterns into exact, prefix, suffix, and general wildcard matchers
// for high-throughput zero-allocation routing on the ingress hot path.
type patternMatcher struct {
	exact    map[string]struct{}
	prefixes []string
	suffixes []string
	wildcard []string
}

func compileMatcher(patterns []string) patternMatcher {
	m := patternMatcher{
		exact: make(map[string]struct{}),
	}
	for _, pattern := range patterns {
		p := strings.ToLower(pattern)
		if strings.ContainsRune(p, '\\') {
			p = strings.ReplaceAll(p, "\\", "/")
		}

		// 1. Literal exact match (no wildcard characters: '*', '?', '[')
		if !strings.ContainsAny(p, "*?[") {
			m.exact[p] = struct{}{}
			continue
		}

		// 2. Pure prefix pattern (e.g. "get_*", non-empty prefix, no other wildcards)
		if len(p) > 1 && strings.HasSuffix(p, "*") && !strings.ContainsAny(p[:len(p)-1], "*?[") {
			m.prefixes = append(m.prefixes, p[:len(p)-1])
			continue
		}

		// 3. Pure suffix pattern (e.g. "*_delete", non-empty suffix, no other wildcards)
		if len(p) > 1 && strings.HasPrefix(p, "*") && !strings.ContainsAny(p[1:], "*?[") {
			m.suffixes = append(m.suffixes, p[1:])
			continue
		}

		// 4. General glob pattern (evaluated via path.Match)
		m.wildcard = append(m.wildcard, p)
	}
	return m
}

func (m *patternMatcher) match(toolLower string) bool {
	if _, ok := m.exact[toolLower]; ok {
		return true
	}
	for _, prefix := range m.prefixes {
		if strings.HasPrefix(toolLower, prefix) {
			return true
		}
	}
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(toolLower, suffix) {
			return true
		}
	}
	for _, pattern := range m.wildcard {
		if matched, _ := path.Match(pattern, toolLower); matched {
			return true
		}
	}
	return false
}

// Router classifies tool invocations into Fast-Path or Deep-Path according to ADR-0010 / TICK-002.
type Router struct {
	mu               sync.RWMutex
	enabled          bool
	defaultPath      PathType
	fastPathPatterns []string
	deepPathPatterns []string
	fastMatcher      patternMatcher
	deepMatcher      patternMatcher
}

// NewRouter creates a new AdaptiveRouter with precompiled matchers.
func NewRouter(enabled bool, defaultPath string, fastPatterns, deepPatterns []string) *Router {
	def := PathDeep
	if strings.EqualFold(defaultPath, "fast") || strings.EqualFold(defaultPath, "fast_path") {
		def = PathFast
	}

	// If no explicit patterns provided, set default read-only conventions
	if len(fastPatterns) == 0 && enabled {
		fastPatterns = []string{"get_*", "list_*", "read_*", "search_*", "query_*", "describe_*", "fetch_*", "view_*"}
	}
	if len(deepPatterns) == 0 && enabled {
		deepPatterns = []string{"delete_*", "remove_*", "execute_*", "exec_*", "run_*", "write_*", "update_*", "send_*", "post_*"}
	}

	fastCopy := make([]string, len(fastPatterns))
	copy(fastCopy, fastPatterns)

	deepCopy := make([]string, len(deepPatterns))
	copy(deepCopy, deepPatterns)

	return &Router{
		enabled:          enabled,
		defaultPath:      def,
		fastPathPatterns: fastCopy,
		deepPathPatterns: deepCopy,
		fastMatcher:      compileMatcher(fastCopy),
		deepMatcher:      compileMatcher(deepCopy),
	}
}

// IsEnabled returns whether adaptive routing is active.
func (r *Router) IsEnabled() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

// Classify determines the PathType for a given tool name.
func (r *Router) Classify(toolName string) PathType {
	if r == nil || !r.enabled || toolName == "" {
		return PathDeep
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	norm := toolName
	if strings.ContainsRune(norm, '\\') {
		norm = strings.ReplaceAll(norm, "\\", "/")
	}
	toolLower := strings.ToLower(norm)

	// 1. Check Deep-Path patterns first (Safety & Zero-Trust Priority)
	if r.deepMatcher.match(toolLower) {
		return PathDeep
	}

	// 2. Check Fast-Path patterns
	if r.fastMatcher.match(toolLower) {
		return PathFast
	}

	// 3. Fallback to default path
	return r.defaultPath
}

// ShouldExecuteFilter checks whether a specific filter should run for the classified PathType.
func (r *Router) ShouldExecuteFilter(filterName string, pathType PathType) bool {
	if pathType == PathDeep {
		return true // Deep-path executes all filters
	}
	// Fast-path only executes low-latency in-memory filters
	return FastPathFilterNames[filterName]
}
