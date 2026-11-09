package mcpconfig

import (
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

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
	normURL := strings.ToLower(strings.TrimSpace(server.URL))

	argsJoined := strings.ToLower(strings.Join(server.Args, " "))

	var matched *protocol.PresetMetadata

	for i := range presets {
		p := &presets[i]
		pID := strings.ToLower(p.ID)

		// 1. Exact name or ID match
		if normName == pID || strings.Contains(normName, pID) {
			matched = p
			break
		}

		// 2. Package / args signature match (e.g. "@modelcontextprotocol/server-github")
		if strings.Contains(argsJoined, pID) {
			matched = p
			break
		}

		// 3. URL match for remote presets (e.g. context7.com, tavily.com)
		if p.URL != "" && normURL != "" {
			pURLClean := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(p.URL), "https://"), "http://")
			sURLClean := strings.TrimPrefix(strings.TrimPrefix(normURL, "https://"), "http://")
			if strings.Contains(sURLClean, strings.Split(pURLClean, "/")[0]) {
				matched = p
				break
			}
		}

		// 4. Command match (e.g. "docker-mcp", "kubectl-mcp")
		if normCmd != "" && strings.Contains(normCmd, pID) {
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
