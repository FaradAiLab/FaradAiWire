package mcpexport

import (
	"context"
	"fmt"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
)

// Export serializes a Security Profile into the requested Target Client's native MCP JSON format.
func Export(ctx context.Context, req ExportRequest) (*ExportResult, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("export cancelled: %w", err)
		}
	}
	if req.Route == nil {
		return nil, fmt.Errorf("agent route configuration is required")
	}

	client := strings.ToLower(strings.TrimSpace(req.Client))
	resolvedScope, pathHint, mergeHazard, err := ResolveTargetMeta(client, req.Scope, req.ClientOS)
	if err != nil {
		return nil, err
	}

	clientOS, _ := NormalizeClientOS(req.ClientOS)

	servers := make(map[string]any, len(req.Route.Protocols))
	usedKeys := make(map[string]int, len(req.Route.Protocols))
	indexedManifest := indexManifestByProtocol(req.Route, req.Manifest)
	var claudeDenyPatterns []string
	var warnings []Warning

	for i, proto := range req.Route.Protocols {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("export cancelled: %w", err)
			}
		}

		serverKey := AllocateServerKey(SanitizeServerKey(proto.Name, proto.ID), usedKeys)

		transportMode := ""
		if req.Lookup != nil && strings.TrimSpace(proto.ID) != "" {
			if stored, ok := req.Lookup(proto.ID); ok && stored != nil {
				transportMode = strings.TrimSpace(stored.TransportMode)
			}
		}

		isStdio := proto.IsStdio()
		if !isStdio && client == ClientClaudeDesktop {
			warnings = append(warnings, Warning{
				Code:     WarnUnsupportedTransportOmitted,
				Severity: SeverityWarning,
				Server:   serverKey,
				Message:  "Claude Desktop claude_desktop_config.json only supports local stdio servers; omitted remote Tool Source. Add it manually via Claude Desktop Settings -> Connectors.",
			})
			continue
		}

		if !isStdio && strings.EqualFold(proto.Type, "sse") && transportMode == "" {
			warnings = append(warnings, Warning{
				Code:     WarnUnverifiedTransportMode,
				Severity: SeverityWarning,
				Server:   serverKey,
				Message:  "Remote transport mode is unverified (persisted as sse without probed transport_mode); verify whether this server requires Streamable HTTP instead of sse.",
			})
		}

		var catalogTools []agent.ToolMetadata
		if indexedManifest != nil {
			catalogTools = indexedManifest[i]
		}
		sel := evaluateSelectedToolsWithCatalog(req.Route, proto, serverKey, catalogTools, client)
		warnings = append(warnings, sel.Warnings...)
		if sel.OmitServer {
			continue
		}
		if len(sel.ClaudeDenyPatterns) > 0 {
			claudeDenyPatterns = append(claudeDenyPatterns, sel.ClaudeDenyPatterns...)
		}

		entry, entryWarnings, err := serializeServerEntry(proto, serverKey, transportMode, client, sel)
		if err != nil {
			return nil, fmt.Errorf("serialize server %q: %w", serverKey, err)
		}
		warnings = append(warnings, entryWarnings...)
		servers[serverKey] = entry
	}

	warnings = append(warnings, Warning{
		Code:     WarnSecurityPoliciesExcluded,
		Severity: SeverityInfo,
		Message:  "FaradAiWire DLP rules, Policy Packs, AI Guard, Rate Limits, Loop Protection, and HITL policies are not exported.",
	})

	result := &ExportResult{
		Client:         client,
		Scope:          resolvedScope,
		TargetPathHint: pathHint,
		MergeHazard:    mergeHazard,
		Config: map[string]any{
			"mcpServers": servers,
		},
		Warnings: deduplicateWarnings(warnings),
	}

	if client == ClientClaudeCode && len(claudeDenyPatterns) > 0 {
		companionHint := ".claude/settings.json"
		if resolvedScope == ScopeGlobal {
			if clientOS == OSWindows {
				companionHint = `%USERPROFILE%\.claude\settings.json`
			} else {
				companionHint = "~/.claude/settings.json"
			}
		}
		result.CompanionFiles = []CompanionFile{
			{
				PathHint:    companionHint,
				MergeHazard: true,
				Content: map[string]any{
					"permissions": map[string]any{
						"deny": claudeDenyPatterns,
					},
				},
			},
		}
	}

	return result, nil
}

func serializeServerEntry(proto agent.ProtocolConfig, serverKey, transportMode, client string, sel SelectionOutcome) (map[string]any, []Warning, error) {
	entry := make(map[string]any)
	var warnings []Warning

	if proto.IsStdio() {
		cmd := strings.TrimSpace(proto.GetCommand())
		args := append([]string(nil), proto.Args...)
		if len(args) == 0 && cmd != "" {
			splitCmd, splitArgs, err := SplitStdioCommand(cmd)
			if err != nil {
				return nil, nil, err
			}
			cmd = splitCmd
			args = splitArgs
		}

		redArgs, argWarnings := RedactArgs(args, client, serverKey)
		warnings = append(warnings, argWarnings...)
		redEnv, envWarnings := RedactEnv(proto.Env, client, serverKey)
		warnings = append(warnings, envWarnings...)

		switch client {
		case ClientClaudeCode, ClientCline, ClientRooCode, ClientGeneric:
			entry["type"] = "stdio"
		}
		entry["command"] = cmd
		if len(redArgs) > 0 {
			entry["args"] = redArgs
		} else {
			entry["args"] = []string{}
		}
		if len(redEnv) > 0 {
			entry["env"] = redEnv
		}
	} else {
		isStreamable := proto.IsStreamableHTTP() || strings.EqualFold(transportMode, "streamable_http")
		redURL, urlWarnings := RedactURL(proto.URLOrCommand, client, serverKey)
		warnings = append(warnings, urlWarnings...)
		redHeaders, headerWarnings := RedactHeaders(serverKey, proto.AuthToken, proto.Headers, client)
		warnings = append(warnings, headerWarnings...)

		switch client {
		case ClientClaudeCode, ClientGeneric:
			if isStreamable {
				entry["type"] = "http"
			} else {
				entry["type"] = "sse"
			}
			entry["url"] = redURL
		case ClientCursor, ClientCursorWorkspace:
			entry["url"] = redURL
		case ClientWindsurf:
			entry["serverUrl"] = redURL
		case ClientCline:
			if isStreamable {
				entry["type"] = "streamableHttp"
			} else {
				entry["type"] = "sse"
			}
			entry["url"] = redURL
		case ClientRooCode:
			if isStreamable {
				entry["type"] = "streamable-http"
			} else {
				entry["type"] = "sse"
			}
			entry["url"] = redURL
		case ClientAntigravity:
			// Antigravity rejects explicit "type" fields and uses "serverUrl".
			entry["serverUrl"] = redURL
		}

		if len(redHeaders) > 0 {
			entry["headers"] = redHeaders
		}
	}

	if client == ClientWindsurf || client == ClientRooCode {
		if sel.DisableServer {
			entry["disabled"] = true
		}
		if len(sel.DisabledTools) > 0 {
			entry["disabledTools"] = sel.DisabledTools
		}
	}

	return entry, warnings, nil
}

func deduplicateWarnings(in []Warning) []Warning {
	if len(in) == 0 {
		return []Warning{}
	}
	seen := make(map[string]bool, len(in))
	out := make([]Warning, 0, len(in))
	for _, w := range in {
		key := w.Code + "|" + w.Server + "|" + w.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, w)
	}
	return out
}
