package mcpconfig

import (
	"net/url"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

func splitIdentifierTokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
}

func matchesPresetToken(text, presetID string) bool {
	if text == "" || presetID == "" {
		return false
	}
	normText := strings.ToLower(strings.TrimSpace(text))
	if normText == presetID {
		return true
	}
	presetTokens := splitIdentifierTokens(presetID)
	if len(presetTokens) == 0 {
		return false
	}
	tokens := splitIdentifierTokens(normText)
	if len(presetTokens) == 1 {
		target := presetTokens[0]
		for _, tok := range tokens {
			if tok == target {
				return true
			}
		}
		return false
	}
	for i := 0; i <= len(tokens)-len(presetTokens); i++ {
		allMatch := true
		for j := range presetTokens {
			if tokens[i+j] != presetTokens[j] {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}

func matchesPresetURL(serverURL, presetURL string) bool {
	if serverURL == "" || presetURL == "" {
		return false
	}
	parsedServer, err1 := url.Parse(strings.TrimSpace(serverURL))
	parsedPreset, err2 := url.Parse(strings.TrimSpace(presetURL))
	if err1 != nil || err2 != nil {
		return false
	}
	sHost := strings.ToLower(parsedServer.Hostname())
	pHost := strings.ToLower(parsedPreset.Hostname())
	if sHost == "" || pHost == "" {
		return false
	}
	return sHost == pHost || strings.HasSuffix(sHost, "."+pHost)
}

// MatchResult contains preset identification and recommended security policy hints for an MCP server.
type MatchResult struct {
	Preset          *protocol.PresetMetadata `json:"preset,omitempty"`
	IsCustom        bool                     `json:"is_custom"`
	RecommendedDLP  []string                 `json:"recommended_dlp"`
	RecommendedHITL []string                 `json:"recommended_hitl"`
}

// MatchPreset compares a discovered server against FaradAiWire's curated preset catalog
// and computes recommended security policy packs and human-in-the-loop guardrails.
func MatchPreset(server DiscoveredServer, presets []protocol.PresetMetadata) MatchResult {
	if len(presets) == 0 {
		presets = protocol.GetPresets()
	}

	normName := strings.ToLower(strings.TrimSpace(server.Name))
	normCmd := strings.ToLower(strings.TrimSpace(server.Command))
	normURL := strings.TrimSpace(server.URL)

	argsJoined := strings.ToLower(strings.Join(server.Args, " "))

	var matched *protocol.PresetMetadata

	for i := range presets {
		p := &presets[i]
		pID := strings.ToLower(p.ID)

		// 1. Exact name or token-bounded ID match
		if normName == pID || matchesPresetToken(normName, pID) {
			matched = p
			break
		}

		// 2. Package / args token signature match (e.g. "@modelcontextprotocol/server-github")
		if matchesPresetToken(argsJoined, pID) {
			matched = p
			break
		}

		// 3. Hostname match for remote presets (e.g. context7.com, tavily.com)
		if matchesPresetURL(normURL, p.URL) {
			matched = p
			break
		}

		// 4. Command token match (e.g. "docker-mcp", "kubectl-mcp")
		if matchesPresetToken(normCmd, pID) {
			matched = p
			break
		}
	}

	res := MatchResult{
		Preset:          matched,
		IsCustom:        matched == nil,
		RecommendedDLP:  []string{},
		RecommendedHITL: []string{},
	}

	// Compute contextual recommendations based on matched category or tool identity
	if matched != nil {
		switch matched.ID {
		case "filesystem":
			res.RecommendedDLP = append(res.RecommendedDLP, "Sensitive Files Block (.env, id_rsa, /etc/passwd)")
			res.RecommendedHITL = append(res.RecommendedHITL, "write_file", "delete_file")
		case "postgres", "sqlite":
			res.RecommendedDLP = append(res.RecommendedDLP, "Database Credentials & Connection String Masking", "Credit Card DLP")
			res.RecommendedHITL = append(res.RecommendedHITL, "execute_query", "drop_table", "delete_record")
		case "github", "git":
			res.RecommendedDLP = append(res.RecommendedDLP, "Personal Access Token Masking (ghp_*, glpat_*)", "Private Key DLP")
			res.RecommendedHITL = append(res.RecommendedHITL, "push_commits", "create_pull_request")
		case "docker", "kubernetes":
			res.RecommendedDLP = append(res.RecommendedDLP, "Cloud IAM & Kubernetes Secret Masking")
			res.RecommendedHITL = append(res.RecommendedHITL, "delete_pod", "stop_container", "apply_manifest")
		default:
			if matched.Category == "data" {
				res.RecommendedDLP = append(res.RecommendedDLP, "PII & Secret Redaction Pack")
			}
		}
	} else {
		// Default generic recommendations for custom tools
		res.RecommendedDLP = append(res.RecommendedDLP, "Default Core Secrets & Credential Masking")
	}

	return res
}
