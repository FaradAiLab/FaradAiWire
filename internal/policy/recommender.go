package policy

import (
	"sort"
	"strings"
)

// RecommendationRequest provides context for analyzing which policy packs should be recommended.
type RecommendationRequest struct {
	ProtocolTypes []string `json:"protocol_types"`
	ProtocolNames []string `json:"protocol_names"`
	ToolNames     []string `json:"tool_names"`
	AttachedPacks []string `json:"attached_packs"`
}

// Recommender evaluates MCP protocols and tool signatures to recommend relevant policy packs.
type Recommender struct{}

// NewRecommender creates a new Recommender instance.
func NewRecommender() *Recommender {
	return &Recommender{}
}

var dbKeywords = []string{
	"postgres", "postgresql", "mysql", "sqlite", "mongodb", "redis", "mssql", "oracle", "mariadb",
	"sql", "query", "database", "table", "schema", "execute_sql", "execute_query", "db_",
}

var cloudKeywords = []string{
	"aws", "gcp", "azure", "cloud", "kubernetes", "k8s", "s3", "iam", "lambda", "ec2",
	"vault", "secret", "secretsmanager", "kms", "blob", "storage",
}

var cmdKeywords = []string{
	"bash", "sh", "exec", "command", "terminal", "run_", "shell", "system", "popen",
}

var fsKeywords = []string{
	"read", "write", "fs", "file", "dir", "path", "filesystem",
}

var netKeywords = []string{
	"http", "curl", "fetch", "url", "webhook", "scrape", "browser",
}

var tokenKeywords = []string{
	"git", "github", "stripe", "slack", "openai", "llm", "api_key",
}

// Recommend analyzes the request and returns deduplicated policy pack recommendations.
func (r *Recommender) Recommend(req RecommendationRequest) []Recommendation {
	attachedSet := make(map[string]struct{}, len(req.AttachedPacks))
	for _, p := range req.AttachedPacks {
		attachedSet[p] = struct{}{}
	}

	recommendations := make([]Recommendation, 0, 6)

	// 1. Check for Database Sanitization
	if _, alreadyAttached := attachedSet["pack:db-sanitization"]; !alreadyAttached {
		matchedTools := r.findMatches(req, dbKeywords)
		if len(matchedTools) > 0 {
			recommendations = append(recommendations, Recommendation{
				PackID:       "pack:db-sanitization",
				PackName:     "Database Sanitization Pack",
				Rationale:    "Database query and connection tools detected. Enforce protection against SQL injection and credential leaks.",
				MatchedTools: matchedTools,
			})
		}
	}

	// 2. Check for Cloud Infrastructure & Secrets
	if _, alreadyAttached := attachedSet["pack:cloud-infra"]; !alreadyAttached {
		matchedTools := r.findMatches(req, cloudKeywords)
		if len(matchedTools) > 0 {
			recommendations = append(recommendations, Recommendation{
				PackID:       "pack:cloud-infra",
				PackName:     "Cloud Infrastructure & Secrets Pack",
				Rationale:    "Cloud infrastructure and secret management tools detected. Prevent leakage of API keys, tokens, and private keys.",
				MatchedTools: matchedTools,
			})
		}
	}

	// 3. Check for Command & Shell Injection
	if _, alreadyAttached := attachedSet["pack:command-injection"]; !alreadyAttached {
		matchedTools := r.findMatches(req, cmdKeywords)
		if len(matchedTools) > 0 {
			recommendations = append(recommendations, Recommendation{
				PackID:       "pack:command-injection",
				PackName:     "Command & Shell Injection Defense Pack",
				Rationale:    "Terminal and OS command execution tools detected. Enforce protection against command chaining, subshells, and destructive execution.",
				MatchedTools: matchedTools,
			})
		}
	}

	// 4. Check for Path Traversal & LFI
	if _, alreadyAttached := attachedSet["pack:path-traversal"]; !alreadyAttached {
		matchedTools := r.findMatches(req, fsKeywords)
		if len(matchedTools) > 0 {
			recommendations = append(recommendations, Recommendation{
				PackID:       "pack:path-traversal",
				PackName:     "Path Traversal & Local File Inclusion Pack",
				Rationale:    "Filesystem and path manipulation tools detected. Defend against directory traversal escapes and access to sensitive system files.",
				MatchedTools: matchedTools,
			})
		}
	}

	// 5. Check for SSRF Defense
	if _, alreadyAttached := attachedSet["pack:ssrf-defense"]; !alreadyAttached {
		matchedTools := r.findMatches(req, netKeywords)
		if len(matchedTools) > 0 {
			recommendations = append(recommendations, Recommendation{
				PackID:       "pack:ssrf-defense",
				PackName:     "Server-Side Request Forgery (SSRF) Defense Pack",
				Rationale:    "Network, HTTP client, and scraping tools detected. Block unauthorized internal egress, loopback requests, and cloud metadata access.",
				MatchedTools: matchedTools,
			})
		}
	}

	// 6. Check for SaaS & Developer Tokens
	if _, alreadyAttached := attachedSet["pack:saas-tokens"]; !alreadyAttached {
		matchedTools := r.findMatches(req, tokenKeywords)
		if len(matchedTools) > 0 {
			recommendations = append(recommendations, Recommendation{
				PackID:       "pack:saas-tokens",
				PackName:     "SaaS & Developer API Tokens Pack",
				Rationale:    "Third-party developer and SaaS API integration tools detected. Guard against accidental leakage of service tokens and API keys.",
				MatchedTools: matchedTools,
			})
		}
	}

	return recommendations
}

func (r *Recommender) findMatches(req RecommendationRequest, keywords []string) []string {
	matched := make(map[string]struct{})

	// Check Protocol Types and Names
	for _, pt := range req.ProtocolTypes {
		lower := strings.ToLower(pt)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				matched[pt] = struct{}{}
				break
			}
		}
	}
	for _, pn := range req.ProtocolNames {
		lower := strings.ToLower(pn)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				matched[pn] = struct{}{}
				break
			}
		}
	}

	// Check Tool Names
	for _, tn := range req.ToolNames {
		lower := strings.ToLower(tn)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				matched[tn] = struct{}{}
				break
			}
		}
	}

	result := make([]string, 0, len(matched))
	for m := range matched {
		result = append(result, m)
	}
	sort.Strings(result)
	return result
}
