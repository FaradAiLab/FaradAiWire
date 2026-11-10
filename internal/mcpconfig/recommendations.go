package mcpconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
)

type dlpPatternJSON struct {
	Name   string `json:"name"`
	Regex  string `json:"regex"`
	Action string `json:"action"`
}

type agentDLPDoc struct {
	Enabled        bool                   `json:"enabled"`
	CustomPatterns []dlpPatternJSON       `json:"custom_patterns"`
	Patterns       []dlpPatternJSON       `json:"patterns"`
	ToolExemptions map[string]interface{} `json:"tool_exemptions,omitempty"`
}

// RecommendationsSummary reports security artifacts persisted from preset matching.
type RecommendationsSummary struct {
	DLPPatternsAdded     int
	HITLGovernanceAdded  int
	DestructiveToolsSeed []string
}

var presetDLPRules = map[string][]dlpPatternJSON{
	"filesystem": {
		{Name: "sensitive_files", Regex: `(?i)(\.env|\.aws/credentials|id_rsa|id_ed25519|/etc/shadow|/etc/passwd)`, Action: "block"},
		{Name: "private_keys", Regex: `-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`, Action: "block"},
	},
	"postgres": {
		{Name: "db_connection_strings", Regex: `(?i)(postgres(?:ql)?|mysql|mongodb)://[^\s"']+`, Action: "mask"},
		{Name: "credit_card", Regex: `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`, Action: "mask"},
	},
	"sqlite": {
		{Name: "db_connection_strings", Regex: `(?i)(postgres(?:ql)?|mysql|mongodb)://[^\s"']+`, Action: "mask"},
		{Name: "credit_card", Regex: `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`, Action: "mask"},
	},
	"github": {
		{Name: "git_personal_access_tokens", Regex: `\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{10,})\b`, Action: "mask"},
		{Name: "private_keys", Regex: `-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`, Action: "block"},
	},
	"git": {
		{Name: "git_personal_access_tokens", Regex: `\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{10,})\b`, Action: "mask"},
		{Name: "private_keys", Regex: `-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`, Action: "block"},
	},
	"docker": {
		{Name: "cloud_iam_keys", Regex: `\b(AKIA|ASIA)[A-Z0-9]{16}\b`, Action: "mask"},
	},
	"kubernetes": {
		{Name: "cloud_iam_keys", Regex: `\b(AKIA|ASIA)[A-Z0-9]{16}\b`, Action: "mask"},
		{Name: "bearer_jwt", Regex: `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, Action: "mask"},
	},
}

var defaultCoreDLPRules = []dlpPatternJSON{
	{Name: "private_keys", Regex: `-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`, Action: "block"},
	{Name: "aws_access_key", Regex: `\b(AKIA|ASIA)[A-Z0-9]{16}\b`, Action: "mask"},
}

// PersistMatchRecommendations materializes MatchPreset recommendations into:
// 1. agents/<profile>/current/dlp.json (merged without overwriting user rules or Enabled toggle)
// 2. agents/<profile>/current/config.json ToolGovernance HITL rules (canonical <protoSlug>__<tool>).
func PersistMatchRecommendations(profileName string, servers []DiscoveredServer, agentsDir, configPath string) (*RecommendationsSummary, error) {
	if err := pathguard.ValidateSafeIdentifier(profileName); err != nil {
		return nil, fmt.Errorf("invalid profile identifier %q: %w", profileName, err)
	}
	if agentsDir == "" {
		agentsDir = filepath.Join(config.DefaultFaradAiWireDir(), "agents")
	}

	agentDir, err := pathguard.ResolveSandboxedPath(agentsDir, profileName)
	if err != nil {
		return nil, fmt.Errorf("resolve profile directory '%s': %w", profileName, err)
	}
	currentDir, err := pathguard.ResolveSandboxedPath(agentDir, "current")
	if err != nil {
		return nil, fmt.Errorf("resolve profile current directory: %w", err)
	}
	if err := os.MkdirAll(currentDir, 0700); err != nil {
		return nil, fmt.Errorf("create profile directory: %w", err)
	}

	presets := protocol.GetPresets()
	desiredPatterns := make(map[string]dlpPatternJSON)
	desiredHITLByTool := make(map[string]agent.ToolGovernanceMode)
	destructiveSet := make(map[string]struct{})

	for _, s := range servers {
		match := MatchPreset(s, presets)
		protoSlug := sanitizeIdentifier(profileName, s.Name)

		var rules []dlpPatternJSON
		if match.Preset != nil {
			rules = presetDLPRules[strings.ToLower(match.Preset.ID)]
		}
		if len(rules) == 0 {
			rules = defaultCoreDLPRules
		}
		for _, r := range rules {
			desiredPatterns[r.Name] = r
		}

		for _, hitlTool := range match.RecommendedHITL {
			if strings.TrimSpace(hitlTool) == "" {
				continue
			}
			destructiveSet[hitlTool] = struct{}{}
			canonical := fmt.Sprintf("%s__%s", protoSlug, hitlTool)
			desiredHITLByTool[canonical] = agent.ModeStrictAlwaysHITL
		}
	}

	summary := &RecommendationsSummary{}

	// 1. Merge into agents/<profile>/current/dlp.json without clobbering existing Enabled toggle
	dlpPath := filepath.Join(currentDir, "dlp.json")
	dlpDoc := agentDLPDoc{
		Enabled:        true,
		CustomPatterns: []dlpPatternJSON{},
		Patterns:       []dlpPatternJSON{},
	}
	if existingData, err := os.ReadFile(dlpPath); err == nil {
		if len(bytes.TrimSpace(existingData)) > 0 {
			if uErr := json.Unmarshal(existingData, &dlpDoc); uErr != nil {
				return nil, fmt.Errorf("parse existing dlp.json '%s': %w", dlpPath, uErr)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read existing dlp.json '%s': %w", dlpPath, err)
	}

	existingPatternNames := make(map[string]struct{}, len(dlpDoc.Patterns)+len(dlpDoc.CustomPatterns))
	for _, p := range dlpDoc.Patterns {
		existingPatternNames[p.Name] = struct{}{}
	}
	for _, p := range dlpDoc.CustomPatterns {
		existingPatternNames[p.Name] = struct{}{}
	}

	patternNames := make([]string, 0, len(desiredPatterns))
	for name := range desiredPatterns {
		patternNames = append(patternNames, name)
	}
	sort.Strings(patternNames)
	for _, name := range patternNames {
		if _, exists := existingPatternNames[name]; !exists {
			dlpDoc.Patterns = append(dlpDoc.Patterns, desiredPatterns[name])
			summary.DLPPatternsAdded++
		}
	}
	dlpBytes, err := json.MarshalIndent(dlpDoc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal dlp.json: %w", err)
	}
	if err := atomicWriteFile(dlpPath, dlpBytes, 0600); err != nil {
		return nil, fmt.Errorf("commit dlp.json '%s': %w", dlpPath, err)
	}

	// 2. Merge HITL ToolGovernance into agents/<profile>/current/config.json if present
	cfgPath := filepath.Join(currentDir, "config.json")
	if cfgData, err := os.ReadFile(cfgPath); err == nil {
		if len(bytes.TrimSpace(cfgData)) > 0 && len(desiredHITLByTool) > 0 {
			var routeCfg agent.RouteConfig
			if uErr := json.Unmarshal(cfgData, &routeCfg); uErr != nil {
				return nil, fmt.Errorf("parse profile config '%s': %w", cfgPath, uErr)
			}
			if routeCfg.ToolGovernance == nil {
				routeCfg.ToolGovernance = make(map[string]agent.ToolGovernanceMode, len(desiredHITLByTool))
			}
			for canonical, mode := range desiredHITLByTool {
				if _, exists := routeCfg.ToolGovernance[canonical]; !exists {
					routeCfg.ToolGovernance[canonical] = mode
					summary.HITLGovernanceAdded++
				}
			}
			if summary.HITLGovernanceAdded > 0 {
				cfgBytes, mErr := json.MarshalIndent(routeCfg, "", "  ")
				if mErr != nil {
					return nil, fmt.Errorf("marshal profile config '%s': %w", cfgPath, mErr)
				}
				if err := atomicWriteFile(cfgPath, cfgBytes, 0600); err != nil {
					return nil, fmt.Errorf("commit profile config '%s': %w", cfgPath, err)
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read profile config '%s': %w", cfgPath, err)
	}

	destructiveList := make([]string, 0, len(destructiveSet))
	for tool := range destructiveSet {
		destructiveList = append(destructiveList, tool)
	}
	sort.Strings(destructiveList)
	summary.DestructiveToolsSeed = destructiveList

	// Per ADR-0053, config.yaml is never rewritten by CLI mutations so user comments and
	// formatting remain pristine; canonical prefixed HITL rules are persisted in agents/<profile>/current/config.json.
	_ = configPath

	return summary, nil
}

// SeedDiscoveredSchemas persists discovered MCP tool schemas and canonical SHA-256 baselines
// into DuckDB mcp_tool_schemas using the shared SchemaFilter normalization logic.
func SeedDiscoveredSchemas(ctx context.Context, profileName string, servers []DiscoveredServer, results []ProbeResult, store schema.Store) (int, error) {
	if store == nil {
		return 0, nil
	}
	if err := pathguard.ValidateSafeIdentifier(profileName); err != nil {
		return 0, fmt.Errorf("invalid profile identifier %q: %w", profileName, err)
	}
	if err := store.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate mcp_tool_schemas: %w", err)
	}

	serverByName := make(map[string]DiscoveredServer, len(servers))
	for _, s := range servers {
		serverByName[s.Name] = s
	}

	now := time.Now().UTC()
	seeded := 0

	for _, pr := range results {
		if !pr.Success || len(pr.Tools) == 0 {
			continue
		}
		if _, ok := serverByName[pr.ServerName]; !ok {
			continue
		}
		protoSlug := sanitizeIdentifier(profileName, pr.ServerName)

		for _, rt := range pr.Tools {
			rawName, _ := rt["name"].(string)
			if rawName == "" {
				continue
			}
			cleanRaw := strings.TrimPrefix(rawName, protoSlug+"__")
			canonical := fmt.Sprintf("%s__%s", protoSlug, cleanRaw)

			inputSchema, _ := rt["inputSchema"].(map[string]interface{})
			if inputSchema == nil {
				inputSchema = map[string]interface{}{"type": "object"}
			}
			rawJSON, err := json.Marshal(inputSchema)
			if err != nil {
				continue
			}
			normalized, err := schema.NormalizeJSON(rawJSON)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(normalized)
			rec := &schema.ToolSchemaRecord{
				ToolName:    canonical,
				ProtocolID:  protoSlug,
				SchemaJSON:  normalized,
				SHA256Hash:  hex.EncodeToString(sum[:]),
				FirstSeenAt: now,
				LastSeenAt:  now,
			}
			if err := store.SaveSchema(ctx, rec); err != nil {
				return seeded, fmt.Errorf("seed schema '%s': %w", canonical, err)
			}
			seeded++
		}
	}
	return seeded, nil
}
