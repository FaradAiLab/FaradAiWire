// Package mcpexport serializes a FaradAiWire Security Profile into Target Client native MCP JSON
// configurations without exposing plaintext credentials or overwriting existing client config files.
package mcpexport

import (
	"fmt"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpconfig"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

// Target Client identifiers supported by Direct Native Export.
const (
	ClientClaudeCode      = string(mcpconfig.ClientClaudeCode)
	ClientClaudeDesktop   = string(mcpconfig.ClientClaudeDesktop)
	ClientCursor          = string(mcpconfig.ClientCursor)
	ClientCursorWorkspace = string(mcpconfig.ClientCursorWorkspace)
	ClientWindsurf        = string(mcpconfig.ClientWindsurf)
	ClientCline           = string(mcpconfig.ClientCline)
	ClientRooCode         = string(mcpconfig.ClientRooCode)
	ClientAntigravity     = string(mcpconfig.ClientAntigravity)
	ClientGeneric         = "generic"
)

// Export scopes.
const (
	ScopeGlobal  = "global"
	ScopeProject = "project"
)

// Target client operating systems used to compute client-accurate path hints.
const (
	OSDarwin  = "darwin"
	OSLinux   = "linux"
	OSWindows = "windows"
)

// Canonical Lossy Export Warning and informational notice codes.
const (
	WarnUnverifiedTransportMode    = "UNVERIFIED_TRANSPORT_MODE"
	WarnUnsupportedTransportOmitted = "UNSUPPORTED_TRANSPORT_OMITTED"
	WarnUncatalogedAllowlistFailOpen = "UNCATALOGED_ALLOWLIST_FAIL_OPEN"
	WarnZeroEffectiveTools         = "ZERO_EFFECTIVE_TOOLS"
	WarnDenylistUpstreamDrift      = "DENYLIST_UPSTREAM_DRIFT"
	WarnSelectedToolsUnsupported   = "SELECTED_TOOLS_UNSUPPORTED"
	WarnEnvDefaultStripped         = "ENV_DEFAULT_STRIPPED"
	WarnEnvInterpolationUnsupported = "ENV_INTERPOLATION_UNSUPPORTED"
	WarnClineEnvOverwriteRisk      = "CLINE_ENV_OVERWRITE_RISK"
	WarnMalformedEnvEntry          = "MALFORMED_ENV_ENTRY"
	WarnSecurityPoliciesExcluded   = "SECURITY_POLICIES_EXCLUDED"
)

// WarningSeverity classifies a Warning entry.
const (
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// ProtocolLookup resolves optional global Tool Source metadata (such as TransportMode) by ID.
type ProtocolLookup func(id string) (*protocol.Protocol, bool)

// ExportRequest configures a deterministic, side-effect-free Direct Native Export.
type ExportRequest struct {
	Client   string
	Scope    string
	ClientOS string
	Route    *agent.RouteConfig
	Manifest []agent.ToolMetadata
	Lookup   ProtocolLookup
}

// Warning represents a structured Lossy Export Warning or informational notice.
type Warning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Server   string `json:"server,omitempty"`
	Message  string `json:"message"`
}

// CompanionFile represents an optional secondary configuration snippet (e.g., Claude Code .claude/settings.json).
type CompanionFile struct {
	PathHint    string         `json:"path_hint"`
	MergeHazard bool           `json:"merge_hazard"`
	Content     map[string]any `json:"content"`
}

// ExportResult is the complete, deterministic Direct Native Export payload.
type ExportResult struct {
	Client         string          `json:"client"`
	Scope          string          `json:"scope"`
	TargetPathHint string          `json:"target_path_hint"`
	MergeHazard    bool            `json:"merge_hazard"`
	Config         map[string]any  `json:"config"`
	CompanionFiles []CompanionFile `json:"companion_files,omitempty"`
	Warnings       []Warning       `json:"warnings"`
}

// IsSupportedClient reports whether client is one of the 8 mcpconfig ClientIDs or "generic".
func IsSupportedClient(client string) bool {
	switch client {
	case ClientClaudeCode,
		ClientClaudeDesktop,
		ClientCursor,
		ClientCursorWorkspace,
		ClientWindsurf,
		ClientCline,
		ClientRooCode,
		ClientAntigravity,
		ClientGeneric:
		return true
	default:
		return false
	}
}

// NormalizeClientOS validates and normalizes clientOS, defaulting empty values to "linux".
func NormalizeClientOS(clientOS string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(clientOS))
	if trimmed == "" {
		return OSLinux, nil
	}
	switch trimmed {
	case OSDarwin, OSLinux, OSWindows:
		return trimmed, nil
	default:
		return "", fmt.Errorf("unsupported client_os %q: must be darwin, linux, or windows", clientOS)
	}
}

// ResolveTargetMeta validates (client, scope, clientOS) and computes the resolved scope,
// client-OS-accurate target_path_hint, and merge_hazard flag without reading host OS state.
func ResolveTargetMeta(client, scope, clientOS string) (resolvedScope string, pathHint string, mergeHazard bool, err error) {
	client = strings.ToLower(strings.TrimSpace(client))
	if !IsSupportedClient(client) {
		return "", "", false, fmt.Errorf("unsupported target client %q", client)
	}
	osName, err := NormalizeClientOS(clientOS)
	if err != nil {
		return "", "", false, err
	}

	reqScope := strings.ToLower(strings.TrimSpace(scope))

	switch client {
	case ClientClaudeCode:
		resolvedScope, err = pickScope(reqScope, ScopeProject, ScopeGlobal, ScopeProject)
		if err != nil {
			return "", "", false, err
		}
		if resolvedScope == ScopeProject {
			return resolvedScope, ".mcp.json", false, nil
		}
		if osName == OSWindows {
			return resolvedScope, `%USERPROFILE%\.claude.json`, true, nil
		}
		return resolvedScope, "~/.claude.json", true, nil

	case ClientClaudeDesktop:
		resolvedScope, err = pickScope(reqScope, ScopeGlobal, ScopeGlobal)
		if err != nil {
			return "", "", false, err
		}
		switch osName {
		case OSDarwin:
			return resolvedScope, "~/Library/Application Support/Claude/claude_desktop_config.json", true, nil
		case OSWindows:
			return resolvedScope, `%APPDATA%\Claude\claude_desktop_config.json`, true, nil
		default:
			return resolvedScope, "~/.config/Claude/claude_desktop_config.json", true, nil
		}

	case ClientCursor:
		resolvedScope, err = pickScope(reqScope, ScopeGlobal, ScopeGlobal)
		if err != nil {
			return "", "", false, err
		}
		if osName == OSWindows {
			return resolvedScope, `%USERPROFILE%\.cursor\mcp.json`, false, nil
		}
		return resolvedScope, "~/.cursor/mcp.json", false, nil

	case ClientCursorWorkspace:
		resolvedScope, err = pickScope(reqScope, ScopeProject, ScopeProject)
		if err != nil {
			return "", "", false, err
		}
		if osName == OSWindows {
			return resolvedScope, `.cursor\mcp.json`, false, nil
		}
		return resolvedScope, ".cursor/mcp.json", false, nil

	case ClientWindsurf:
		resolvedScope, err = pickScope(reqScope, ScopeGlobal, ScopeGlobal)
		if err != nil {
			return "", "", false, err
		}
		if osName == OSWindows {
			return resolvedScope, `%USERPROFILE%\.codeium\windsurf\mcp_config.json`, false, nil
		}
		return resolvedScope, "~/.codeium/windsurf/mcp_config.json", false, nil

	case ClientCline:
		resolvedScope, err = pickScope(reqScope, ScopeGlobal, ScopeGlobal)
		if err != nil {
			return "", "", false, err
		}
		switch osName {
		case OSDarwin:
			return resolvedScope, "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", false, nil
		case OSWindows:
			return resolvedScope, `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`, false, nil
		default:
			return resolvedScope, "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", false, nil
		}

	case ClientRooCode:
		resolvedScope, err = pickScope(reqScope, ScopeGlobal, ScopeGlobal, ScopeProject)
		if err != nil {
			return "", "", false, err
		}
		if resolvedScope == ScopeProject {
			if osName == OSWindows {
				return resolvedScope, `.roo\mcp.json`, false, nil
			}
			return resolvedScope, ".roo/mcp.json", false, nil
		}
		switch osName {
		case OSDarwin:
			return resolvedScope, "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json", false, nil
		case OSWindows:
			return resolvedScope, `%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json`, false, nil
		default:
			return resolvedScope, "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json", false, nil
		}

	case ClientAntigravity:
		resolvedScope, err = pickScope(reqScope, ScopeGlobal, ScopeGlobal, ScopeProject)
		if err != nil {
			return "", "", false, err
		}
		if resolvedScope == ScopeProject {
			if osName == OSWindows {
				return resolvedScope, `.agents\mcp_config.json`, false, nil
			}
			return resolvedScope, ".agents/mcp_config.json", false, nil
		}
		if osName == OSWindows {
			return resolvedScope, `%USERPROFILE%\.gemini\antigravity\mcp_config.json`, false, nil
		}
		return resolvedScope, "~/.gemini/antigravity/mcp_config.json", false, nil

	case ClientGeneric:
		resolvedScope, err = pickScope(reqScope, ScopeProject, ScopeGlobal, ScopeProject)
		if err != nil {
			return "", "", false, err
		}
		return resolvedScope, "mcp-servers.json", false, nil
	}

	return "", "", false, fmt.Errorf("unsupported target client %q", client)
}

func pickScope(requested, defaultScope string, allowed ...string) (string, error) {
	if requested == "" {
		return defaultScope, nil
	}
	for _, a := range allowed {
		if requested == a {
			return requested, nil
		}
	}
	return "", fmt.Errorf("scope %q is not supported for this client (allowed: %s)", requested, strings.Join(allowed, ", "))
}
