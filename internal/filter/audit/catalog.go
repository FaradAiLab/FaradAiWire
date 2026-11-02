package audit

import (
	"fmt"
	"regexp"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

// ThreatCategory defines the canonical high-level security category for audit findings.
type ThreatCategory string

const (
	CategoryShellExecution       ThreatCategory = "shell_execution"
	CategoryCredentialHarvesting ThreatCategory = "credential_harvesting"
	CategoryDestructiveCommands  ThreatCategory = "destructive_commands"
	CategoryPrivilegeEscalation  ThreatCategory = "privilege_escalation"
	CategoryDangerousEval        ThreatCategory = "dangerous_eval"
	CategoryNetworkBackdoor      ThreatCategory = "network_backdoor"
	CategoryOpaqueBinary         ThreatCategory = "opaque_binary"
)

// HumanReadableName returns the user-facing description of the category.
func (c ThreatCategory) HumanReadableName() string {
	switch c {
	case CategoryShellExecution:
		return "Malicious shell invocations & command chaining"
	case CategoryCredentialHarvesting:
		return "Credential harvesting & secret leakage signatures"
	case CategoryDestructiveCommands:
		return "Destructive system commands & disk formatting"
	case CategoryPrivilegeEscalation:
		return "Privilege escalation & sudoer manipulation"
	case CategoryDangerousEval:
		return "Obfuscated & dangerous runtime eval/exec execution"
	case CategoryNetworkBackdoor:
		return "Reverse shells & unauthorized outbound backdoors"
	case CategoryOpaqueBinary:
		return "Opaque compiled binary payloads"
	default:
		return string(c)
	}
}

// AuditRule represents a compiled, high-performance regex pattern for static scanning.
type AuditRule struct {
	ID          string
	Name        string
	Category    ThreatCategory
	Severity    string // "CRITICAL", "HIGH", "WARNING", "INFO"
	Reason      string
	Pattern     *regexp.Regexp
	RawRegex    string
}

// LoadAuditRuleCatalog builds and compiles the in-memory static audit rule catalog.
// It directly reuses FaradAiWire's canonical built-in policy rules without any
// database, configuration file, or daemon dependency (<1ms execution).
func LoadAuditRuleCatalog() ([]AuditRule, error) {
	builtinRules := policy.BuiltinRules()
	ruleMap := make(map[string]policy.DlpPatternRule, len(builtinRules))
	for _, r := range builtinRules {
		ruleMap[r.ID] = r
	}

	// 1. Map canonical rules from policy packs
	type ruleMapping struct {
		ruleID   string
		category ThreatCategory
		severity string
		reason   string
	}

	policyMappings := []ruleMapping{
		// pack:command-injection
		{
			ruleID:   "rule:cmd-reverse-shell",
			category: CategoryNetworkBackdoor,
			severity: "CRITICAL",
			reason:   "Reverse shell spawning or interactive netcat listener pattern",
		},
		{
			ruleID:   "rule:cmd-destructive-rm",
			category: CategoryDestructiveCommands,
			severity: "CRITICAL",
			reason:   "Destructive forced deletion targeting root or wildcard path (rm -rf)",
		},
		{
			ruleID:   "rule:cmd-pipe-to-shell",
			category: CategoryShellExecution,
			severity: "CRITICAL",
			reason:   "Piping remote/unverified content directly into shell interpreter",
		},
		{
			ruleID:   "rule:cmd-chaining-pipe",
			category: CategoryShellExecution,
			severity: "HIGH",
			reason:   "Shell command chaining operator invoking sensitive system binaries",
		},
		{
			ruleID:   "rule:cmd-substitution",
			category: CategoryShellExecution,
			severity: "HIGH",
			reason:   "Subshell execution syntax detected (`...` or $(...))",
		},
		{
			ruleID:   "rule:cmd-sensitive-cat",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Attempting to read sensitive system authentication or password files",
		},
		{
			ruleID:   "rule:cmd-windows-shell",
			category: CategoryShellExecution,
			severity: "HIGH",
			reason:   "Windows command shell execution chain (cmd.exe, powershell, certutil)",
		},

		// pack:cloud-secrets
		{
			ruleID:   "rule:cloud-aws-key",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded AWS Access Key ID detected",
		},
		{
			ruleID:   "rule:cloud-aws-secret",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded AWS Secret Access Key signature detected",
		},
		{
			ruleID:   "rule:cloud-gcp-key",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded Google Cloud API Key detected",
		},
		{
			ruleID:   "rule:cloud-private-key",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded RSA, EC, or OpenSSH private key block detected",
		},
		{
			ruleID:   "rule:cloud-jwt",
			category: CategoryCredentialHarvesting,
			severity: "HIGH",
			reason:   "Hardcoded JSON Web Token (JWT) detected",
		},

		// pack:api-tokens
		{
			ruleID:   "rule:token-openai",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded OpenAI API key detected",
		},
		{
			ruleID:   "rule:token-github-pat",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded GitHub Personal Access Token detected",
		},
		{
			ruleID:   "rule:token-stripe",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded Stripe API secret key detected",
		},
		{
			ruleID:   "rule:token-slack",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded Slack API token detected",
		},
		{
			ruleID:   "rule:token-google-api",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Hardcoded Google AI/Cloud API key detected",
		},

		// pack:path-traversal
		{
			ruleID:   "rule:path-sensitive-unix",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Accessing sensitive user directory path (~/.ssh, ~/.aws, /etc/shadow)",
		},
		{
			ruleID:   "rule:path-dot-dot",
			category: CategoryCredentialHarvesting,
			severity: "HIGH",
			reason:   "Directory traversal escape sequence detected (../)",
		},
	}

	rules := make([]AuditRule, 0, len(policyMappings)+12)

	for _, m := range policyMappings {
		pRule, exists := ruleMap[m.ruleID]
		if !exists {
			continue
		}
		rawRegex := pRule.Regex
		// Precision tuning for static file audit:
		// Bare backticks like `language` are ubiquitous in Markdown/JSON docs.
		// In static code scanning, command substitution requires subshell syntax $(...)
		// or backticks invoking executable system commands.
		if m.ruleID == "rule:cmd-substitution" {
			rawRegex = `(?:\$\([a-zA-Z0-9_\-\.\/ ]+\)|` + "`" + `\s*(?:cat|rm|nc|curl|wget|bash|sh|whoami|id|chmod|chown|kill|pkill|uname|hostname|perl|python|ruby)\b[^` + "`" + `]*` + "`" + `)`
		}

		compiled, err := regexp.Compile(rawRegex)
		if err != nil {
			return nil, fmt.Errorf("compile policy rule %s: %w", m.ruleID, err)
		}
		rules = append(rules, AuditRule{
			ID:       pRule.ID,
			Name:     pRule.Name,
			Category: m.category,
			Severity: m.severity,
			Reason:   m.reason,
			Pattern:  compiled,
			RawRegex: rawRegex,
		})
	}

	// 2. Specialized static rules dedicated to agent skill threats
	specializedRules := []struct {
		id       string
		name     string
		category ThreatCategory
		severity string
		reason   string
		regex    string
	}{
		// Dangerous Runtime Eval & Obfuscation
		{
			id:       "audit:eval-atob",
			name:     "Obfuscated JavaScript Eval Execution",
			category: CategoryDangerousEval,
			severity: "CRITICAL",
			reason:   "Dynamic code execution via eval(atob(...)) or Buffer deobfuscation",
			regex:    `(?i)\beval\s*\(\s*(?:atob|Buffer\.from|window\.atob|unescape)\b`,
		},
		{
			id:       "audit:exec-base64",
			name:     "Obfuscated Python Exec Execution",
			category: CategoryDangerousEval,
			severity: "CRITICAL",
			reason:   "Dynamic Python execution via exec(base64.b64decode(...))",
			regex:    `(?i)\b(?:exec|eval)\s*\(\s*(?:base64\.(?:b64decode|decodebytes)|zlib\.decompress)\b`,
		},
		{
			id:       "audit:python-dynamic-import",
			name:     "Dynamic Python Builtin Execution",
			category: CategoryDangerousEval,
			severity: "HIGH",
			reason:   "Obfuscated execution using __import__ or compile() inside eval",
			regex:    `(?i)\b(?:eval|exec)\s*\(\s*(?:__import__|compile)\b`,
		},

		// Privilege Escalation
		{
			id:       "audit:privilege-sudo-doas",
			name:     "Privilege Escalation Command (sudo/doas)",
			category: CategoryPrivilegeEscalation,
			severity: "CRITICAL",
			reason:   "Elevating execution privileges using sudo, doas, or modifying sudoers",
			regex:    `(?i)\b(?:sudo|doas)\s+[^#\n]+|\b(?:setuid|setgid)\b|/etc/sudoers`,
		},
		{
			id:       "audit:chmod-suid-777",
			name:     "Insecure Permissions or SUID Flag",
			category: CategoryPrivilegeEscalation,
			severity: "WARNING",
			reason:   "Setting world-writable permissions (chmod 777) or SUID bit (chmod +s)",
			regex:    `(?i)\bchmod\s+(?:777|[+]s|[0-7]?[421]777)\b`,
		},

		// Destructive Commands
		{
			id:       "audit:raw-disk-format",
			name:     "Raw Disk Formatting Utility",
			category: CategoryDestructiveCommands,
			severity: "CRITICAL",
			reason:   "Attempting raw filesystem creation or partition manipulation (mkfs/fdisk)",
			regex:    `(?i)\b(?:mkfs|mkfs\.[a-z0-9]+|fdisk|parted|sfdisk)\s+`,
		},
		{
			id:       "audit:dd-zero-destruction",
			name:     "Raw Disk Overwrite with dd",
			category: CategoryDestructiveCommands,
			severity: "CRITICAL",
			reason:   "Overwriting raw disks or partitions from /dev/zero or /dev/urandom",
			regex:    `(?i)\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/`,
		},
		{
			id:       "audit:fork-bomb",
			name:     "Classic Shell Fork Bomb",
			category: CategoryDestructiveCommands,
			severity: "CRITICAL",
			reason:   "Denial-of-service shell resource exhaustion fork bomb",
			regex:    `:\(\)\s*\{\s*:\|:&\s*\};:`,
		},

		// Reverse Shell & Network Backdoors
		{
			id:       "audit:dev-tcp-shell",
			name:     "Bash Raw Socket Redirection (/dev/tcp)",
			category: CategoryNetworkBackdoor,
			severity: "CRITICAL",
			reason:   "Direct socket redirection via /dev/tcp commonly used in reverse shells",
			regex:    `/dev/tcp/(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9_\-\.]+)/\d+`,
		},
		{
			id:       "audit:python-pty-shell",
			name:     "Python PTY Interactive Spawn",
			category: CategoryNetworkBackdoor,
			severity: "CRITICAL",
			reason:   "Spawning interactive PTY shell via Python socket bridge",
			regex:    `(?i)python[23]?\s+-c\s+.*(?:pty\.spawn|socket\.connect|socket\.socket)`,
		},
		{
			id:       "audit:curl-pipe-shell",
			name:     "Downloading Remote Script to Shell",
			category: CategoryShellExecution,
			severity: "CRITICAL",
			reason:   "Downloading unverified remote script directly into shell interpreter",
			regex:    `(?i)(?:curl|wget)\s+.*\|\s*(?:ba|z)?sh\b`,
		},

		// Credential Harvesting
		{
			id:       "audit:aws-credentials-harvest",
			name:     "AWS Credentials File Access",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Attempting to read local AWS CLI credentials or profiles",
			regex:    `(?i)(?:cat|grep|awk|sed|head|tail)?\s*(?:~|\$HOME|\/home\/[^\/]+|\/Users\/[^\/]+)?\/\.aws\/(?:credentials|config)`,
		},
		{
			id:       "audit:env-dump-harvest",
			name:     "Environment Secret Dumping",
			category: CategoryCredentialHarvesting,
			severity: "CRITICAL",
			reason:   "Dumping environment variables searching for keys, tokens, or passwords",
			regex:    `(?i)\b(?:env|printenv|set)\b.*\b(?:grep|awk|sed)?.*\b(?:KEY|SECRET|TOKEN|PASS(?:WORD)?)\b`,
		},
	}

	for _, s := range specializedRules {
		compiled, err := regexp.Compile(s.regex)
		if err != nil {
			return nil, fmt.Errorf("compile specialized audit rule %s: %w", s.id, err)
		}
		rules = append(rules, AuditRule{
			ID:       s.id,
			Name:     s.name,
			Category: s.category,
			Severity: s.severity,
			Reason:   s.reason,
			Pattern:  compiled,
			RawRegex: s.regex,
		})
	}

	return rules, nil
}
