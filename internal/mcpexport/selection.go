package mcpexport

import (
	"fmt"
	"slices"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

// SelectionOutcome captures the Selected Tools evaluation for one Tool Source.
type SelectionOutcome struct {
	OmitServer         bool
	DisableServer      bool
	DisabledTools      []string
	ClaudeDenyPatterns []string
	Warnings           []Warning
}

// EvaluateSelectedTools resolves Layer 1 ∩ Layer 2 Selected Tools for proto and maps them to
// the Target Client's 3-tier filtering capability without substituting auto-approval fields.
func EvaluateSelectedTools(route *agent.RouteConfig, proto agent.ProtocolConfig, serverKey string, manifest []agent.ToolMetadata, client string) SelectionOutcome {
	// Filter manifest strictly to tools belonging to this attached protocol (discarding orphans).
	catalogTools := collectProtocolManifestTools(route, proto, manifest)
	return evaluateSelectedToolsWithCatalog(route, proto, serverKey, catalogTools, client)
}

func evaluateSelectedToolsWithCatalog(route *agent.RouteConfig, proto agent.ProtocolConfig, serverKey string, catalogTools []agent.ToolMetadata, client string) SelectionOutcome {
	var outcome SelectionOutcome

	layer2List := resolveLayer2List(route)
	hasRestrictions := len(proto.AllowedTools) > 0 || len(layer2List) > 0

	if !hasRestrictions {
		return outcome
	}

	if len(catalogTools) == 0 {
		outcome.Warnings = append(outcome.Warnings, Warning{
			Code:     WarnUncatalogedAllowlistFailOpen,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  "Selected Tools allowlist is configured, but no tools are cataloged in tools_manifest.json; server exported with all upstream tools enabled (fail-open). Run tool sync before exporting if filtering is required.",
		})
		return outcome
	}

	var allowedRaw []string
	var deniedRaw []string
	for _, t := range catalogTools {
		raw := effectiveRawToolName(t, proto)
		if isToolPermittedForProtocol(t, raw, proto, layer2List) {
			allowedRaw = append(allowedRaw, raw)
		} else {
			deniedRaw = append(deniedRaw, raw)
		}
	}

	if len(allowedRaw) == 0 {
		outcome.Warnings = append(outcome.Warnings, Warning{
			Code:     WarnZeroEffectiveTools,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  "Selected Tools restrictions matched 0 cataloged tools for this server; check for allowlist typos or intentional full disable.",
		})
		if client == ClientWindsurf || client == ClientRooCode {
			outcome.DisableServer = true
		} else {
			outcome.OmitServer = true
		}
		return outcome
	}

	if len(deniedRaw) == 0 {
		return outcome
	}

	slices.Sort(deniedRaw)
	deniedRaw = slices.Compact(deniedRaw)

	switch client {
	case ClientWindsurf, ClientRooCode:
		outcome.DisabledTools = deniedRaw
		outcome.Warnings = append(outcome.Warnings, Warning{
			Code:     WarnDenylistUpstreamDrift,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  fmt.Sprintf("%s uses a disabledTools denylist (%d tools excluded); newly added upstream tools will be permitted until re-exported.", client, len(deniedRaw)),
		})
	case ClientClaudeCode:
		patterns := make([]string, 0, len(deniedRaw))
		for _, raw := range deniedRaw {
			patterns = append(patterns, fmt.Sprintf("mcp__%s__%s", serverKey, raw))
		}
		outcome.ClaudeDenyPatterns = patterns
		outcome.Warnings = append(outcome.Warnings, Warning{
			Code:     WarnDenylistUpstreamDrift,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  fmt.Sprintf("Claude Code companion permissions.deny excludes %d tools; newly added upstream tools remain permitted until re-exported.", len(deniedRaw)),
		})
	default:
		outcome.Warnings = append(outcome.Warnings, Warning{
			Code:     WarnSelectedToolsUnsupported,
			Severity: SeverityWarning,
			Server:   serverKey,
			Message:  fmt.Sprintf("%s does not support verified per-tool MCP JSON filtering; all %d upstream tools on this server will be exposed (fail-open).", client, len(catalogTools)),
		})
	}

	return outcome
}

func resolveLayer2List(route *agent.RouteConfig) []string {
	if route == nil {
		return nil
	}
	if route.ToolOverrides != nil && len(route.ToolOverrides.EnabledTools) > 0 {
		return route.ToolOverrides.EnabledTools
	}
	if len(route.EnabledTools) > 0 {
		return route.EnabledTools
	}
	return nil
}

func indexManifestByProtocol(route *agent.RouteConfig, manifest []agent.ToolMetadata) [][]agent.ToolMetadata {
	if route == nil || len(route.Protocols) == 0 || len(manifest) == 0 {
		return nil
	}
	byID := make(map[string]int, len(route.Protocols))
	byName := make(map[string]int, len(route.Protocols))
	for i, p := range route.Protocols {
		if id := strings.ToLower(strings.TrimSpace(p.ID)); id != "" {
			if _, exists := byID[id]; !exists {
				byID[id] = i
			}
		}
		if name := strings.ToLower(strings.TrimSpace(p.Name)); name != "" {
			if _, exists := byName[name]; !exists {
				byName[name] = i
			}
		}
	}

	indexed := make([][]agent.ToolMetadata, len(route.Protocols))
	for _, t := range manifest {
		idx := -1
		if id := strings.ToLower(strings.TrimSpace(t.ProtocolID)); id != "" {
			if found, ok := byID[id]; ok {
				idx = found
			} else if found, ok := byName[id]; ok {
				idx = found
			}
		}
		if idx < 0 && t.ProtocolName != "" {
			name := strings.ToLower(strings.TrimSpace(t.ProtocolName))
			if found, ok := byID[name]; ok {
				idx = found
			} else if found, ok := byName[name]; ok {
				idx = found
			}
		}
		if idx >= 0 {
			indexed[idx] = append(indexed[idx], t)
		}
	}
	return indexed
}

func collectProtocolManifestTools(route *agent.RouteConfig, proto agent.ProtocolConfig, manifest []agent.ToolMetadata) []agent.ToolMetadata {
	var tools []agent.ToolMetadata
	for _, t := range manifest {
		if route != nil {
			matched := route.FindProtocol(t.ProtocolID)
			if matched == nil && t.ProtocolName != "" {
				matched = route.FindProtocol(t.ProtocolName)
			}
			if matched == nil {
				continue // Discard orphaned tools from detached protocols.
			}
			if !strings.EqualFold(matched.ID, proto.ID) && !strings.EqualFold(matched.Name, proto.Name) {
				continue
			}
		} else if !strings.EqualFold(t.ProtocolID, proto.ID) && !strings.EqualFold(t.ProtocolName, proto.Name) {
			continue
		}
		tools = append(tools, t)
	}
	return tools
}

func effectiveRawToolName(t agent.ToolMetadata, proto agent.ProtocolConfig) string {
	if strings.TrimSpace(t.RawName) != "" {
		return t.RawName
	}
	slug := agent.GetProtocolSlug(&proto)
	if slug != "" && strings.HasPrefix(strings.ToLower(t.Name), strings.ToLower(slug+"__")) {
		return t.Name[len(slug)+2:]
	}
	return t.Name
}

func isToolPermittedForProtocol(t agent.ToolMetadata, raw string, proto agent.ProtocolConfig, layer2List []string) bool {
	if len(proto.AllowedTools) > 0 && !matchesAllowlist(proto.AllowedTools, t, raw, proto) {
		return false
	}
	if len(layer2List) > 0 && !matchesAllowlist(layer2List, t, raw, proto) {
		return false
	}
	return true
}

func matchesAllowlist(entries []string, t agent.ToolMetadata, raw string, proto agent.ProtocolConfig) bool {
	slug := agent.GetProtocolSlug(&proto)
	for _, entry := range entries {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if strings.EqualFold(e, raw) ||
			(t.Name != "" && strings.EqualFold(e, t.Name)) ||
			(t.CanonicalName != "" && strings.EqualFold(e, t.CanonicalName)) {
			return true
		}
		if prefix, toolPart, ok := strings.Cut(e, "__"); ok {
			if prefixMatchesProtocol(prefix, proto, slug) {
				if strings.EqualFold(toolPart, raw) {
					return true
				}
				if slug != "" && t.Name != "" && strings.EqualFold(agent.FormatAggregatedToolName(slug, toolPart), t.Name) {
					return true
				}
			}
		}
	}
	return false
}

func prefixMatchesProtocol(prefix string, proto agent.ProtocolConfig, slug string) bool {
	return strings.EqualFold(prefix, proto.ID) ||
		strings.EqualFold(prefix, proto.Name) ||
		(slug != "" && strings.EqualFold(prefix, slug)) ||
		(slug != "" && strings.EqualFold(prefix, agent.CompactLegacyProtocolSlug(slug)))
}
