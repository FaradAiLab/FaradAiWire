package main

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// printRootUsage renders the primary CLI command overview with clean columnar alignment.
func printRootUsage(out io.Writer) {
	fmt.Fprintf(out, "FaradAiWire - Zero-Trust AI Agent Security Gateway (%s)\n\n", version)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire <command> [flags] [arguments]")
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Core Commands:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  run\tStart the FaradAiWire security gateway proxy and admin console")
	fmt.Fprintln(w, "  connect\tSpawn or attach an interactive client session to the gateway")
	fmt.Fprintln(w, "  adopt\tDiscover and securely import client IDE configurations")
	fmt.Fprintln(w, "  export\tExport a Security Profile's Tool Sources into native client MCP JSON")
	fmt.Fprintln(w, "  token\tDisplay the active Bootstrap Master Key and one-click Admin Magic Link")
	w.Flush()
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Security & Policy:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  guard\tManage neural guardrail models (list, status, install, uninstall)")
	fmt.Fprintln(w, "  skill-audit\tScan protocols, tools, or repositories for security threats")
	fmt.Fprintln(w, "  audit\tVerify cryptographic integrity of DuckDB and JSONL audit trails")
	w.Flush()
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Diagnostics:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  doctor\tInspect environment, configuration, ports, and neural engines")
	fmt.Fprintln(w, "  version\tPrint the FaradAiWire binary version information")
	w.Flush()
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Flags:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -h, --help\tShow help for faradaiwire or a specific subcommand")
	w.Flush()
	fmt.Fprintln(out)

	fmt.Fprintln(out, `Use "faradaiwire <command> --help" for detailed documentation on a command.`)
}

// printRunUsage prints detailed flag and usage information for 'faradaiwire run'.
func printRunUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire run [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Starts the FaradAiWire security gateway proxy and web admin console.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -host <host>\tHost address to bind HTTP listeners to (default: 127.0.0.1)")
	fmt.Fprintln(w, "  -port <port>\tIngress port to listen on (default: 19410)")
	fmt.Fprintln(w, "  -admin-host <host>\tHost address to bind Admin console listener to (default: 127.0.0.1)")
	fmt.Fprintln(w, "  -admin-port <port>\tAdmin console port to listen on (default: 19415)")
	fmt.Fprintln(w, "  -h, --help\tShow help for run command")
	w.Flush()
}

// printAdoptUsage prints flag and usage documentation for 'faradaiwire adopt'.
func printAdoptUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire adopt [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Discovers MCP clients (Google Antigravity, Claude Desktop, Cursor, Windsurf, Claude Code, Cline, Roo Code) and securely routes them through the gateway.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (default: auto-detected ~/.faradaiwire/config.yaml)")
	fmt.Fprintln(w, "  -rollback\tRevert client configurations back to pristine pre-adoption backups")
	fmt.Fprintln(w, "  -dry-run\tPreview planned adoption changes without mutating files on disk")
	fmt.Fprintln(w, "  -y, -yes\tAutomatically accept all adoption prompts without interactive confirmation")
	fmt.Fprintln(w, "  -workspace\tAlso scan workspace-local ./.cursor/mcp.json (review untrusted commands carefully)")
	fmt.Fprintln(w, "  -servers <list>\tComma-separated list of MCP server names to adopt (default: all discovered)")
	fmt.Fprintln(w, "  -probe-timeout <duration>\tOverride per-server MCP tool discovery probe timeout (default: gateway setting or 5s)")
	fmt.Fprintln(w, "  -backup-dir <path>\tCustom directory to store client configuration backups (default: ~/.faradaiwire/backups)")
	fmt.Fprintln(w, "  -protocols-dir <path>\tDirectory to store imported Tool Sources (default: ~/.faradaiwire/protocols)")
	fmt.Fprintln(w, "  -agents-dir <path>\tDirectory to store client Security Profiles (default: ~/.faradaiwire/agents)")
	fmt.Fprintln(w, "  -h, --help\tShow help for adopt command")
	w.Flush()
}

// printConnectUsage prints flag and usage documentation for 'faradaiwire connect'.
func printConnectUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire connect [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Establishes a local stdio-to-SSE bridge connected to a running FaradAiWire gateway instance.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -profile <name>\tTarget Security Profile name to route traffic through (default: \"default\")")
	fmt.Fprintln(w, "  -host <host>\tGateway ingress host address (default: 127.0.0.1)")
	fmt.Fprintln(w, "  -port <port>\tGateway ingress port (default: active config or 19410)")
	fmt.Fprintln(w, "  -token <token>\tOptional API bearer token (autodiscovered if omitted)")
	fmt.Fprintln(w, "  -no-spawn\tDo not auto-spawn the background daemon if offline")
	fmt.Fprintln(w, "  -h, --help\tShow help for connect command")
	w.Flush()
}

// printTokenUsage prints flag and usage documentation for 'faradaiwire token'.
func printTokenUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire token [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Displays the active Bootstrap Master Key (Admin) and one-click Magic Link without acquiring locks.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file")
	fmt.Fprintln(w, "  -rotate\tAtomically revoke prior Admin keys and generate a fresh Bootstrap Master Key")
	fmt.Fprintln(w, "  -host <host>\tHostname to embed in the Magic Link URL")
	fmt.Fprintln(w, "  -port <port>\tAdmin port to embed in the Magic Link URL")
	fmt.Fprintln(w, "  -json\tOutput token metadata and Magic Link as JSON")
	fmt.Fprintln(w, "  -h, --help\tShow help for token command")
	w.Flush()
}

// printDoctorUsage prints usage documentation for 'faradaiwire doctor'.
func printDoctorUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire doctor [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Runs diagnostic health checks on host environment, system dependencies, configuration, and neural models.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -h, --help\tShow help for doctor command")
	w.Flush()
}

// printSkillAuditUsage prints argument and usage documentation for 'faradaiwire skill-audit'.
func printSkillAuditUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire skill-audit <path|url> [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Scans local skill directories, files, or remote git repositories for security threats.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Arguments:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  <path|url>\tLocal filesystem path or remote git repository URL to scan")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -json\tOutput scan report as structured JSON")
	fmt.Fprintln(w, "  -h, --help\tShow help for skill-audit command")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Exit Codes:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  0\tPASSED — No threat signatures detected")
	fmt.Fprintln(w, "  1\tERROR — Scan aborted, missing path, or invalid arguments")
	fmt.Fprintln(w, "  2\tFAILED — Security threat signatures detected")
	w.Flush()
}

// printAuditUsage prints usage documentation for 'faradaiwire audit'.
func printAuditUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire audit <command> [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Available Commands:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  verify\tVerify tamper-evident integrity across DuckDB audit tables and rotated JSONL segments")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags for \"audit verify\":")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  --config <path>\tPath to YAML configuration file")
	fmt.Fprintln(w, "  --db <path>\tPath to DuckDB telemetry file")
	fmt.Fprintln(w, "  --jsonl <path>\tPath to active audit JSONL log file")
	fmt.Fprintln(w, "  --json\tOutput structured JSON verification report")
	fmt.Fprintln(w, "  -h, --help\tShow help for audit command")
	w.Flush()
}

// printGuardUsageTo renders full guard command options with tab-aligned descriptions.
func printGuardUsageTo(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire guard <command> [flags] [arguments]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Manage neural guardrail models, inspect runtime health, and install/uninstall model weights.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Available Commands:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  list\tDisplay curated guard model catalog with RAM, latency, and benchmark metrics")
	fmt.Fprintln(w, "  status\tReport active guard process state (PID, RSS memory, health status)")
	fmt.Fprintln(w, "  install <id>\tInstall guard model weights and environment")
	fmt.Fprintln(w, "  uninstall <id>\tUninstall guard model weights and revert catalog state")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -h, --help\tShow help for guard command")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, `Use "faradaiwire guard <command> --help" for detailed documentation on a subcommand.`)
}

// printGuardListUsage prints usage documentation for 'faradaiwire guard list'.
func printGuardListUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire guard list [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Display curated guard model catalog with RAM, latency, and benchmark metrics.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -h, --help\tShow help for list command")
	w.Flush()
}

// printGuardStatusUsage prints usage documentation for 'faradaiwire guard status'.
func printGuardStatusUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire guard status [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Report active guard process state (PID, RSS memory, health status).")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -h, --help\tShow help for status command")
	w.Flush()
}

// printGuardInstallUsage prints usage documentation for 'faradaiwire guard install'.
func printGuardInstallUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire guard install <id> [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Downloads and installs neural guardrail model weights into the local model directory.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Arguments:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  <id>\tTarget model ID from catalog (e.g. faradai-guard-base)")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -h, --help\tShow help for install command")
	w.Flush()
}

// printGuardUninstallUsage prints usage documentation for 'faradaiwire guard uninstall'.
func printGuardUninstallUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire guard uninstall <id> [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Uninstalls neural guardrail model weights and purges model files from disk.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Arguments:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  <id>\tTarget model ID to purge")
	w.Flush()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w = tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -config <path>\tPath to YAML configuration file (autodiscovers if omitted)")
	fmt.Fprintln(w, "  -h, --help\tShow help for uninstall command")
	w.Flush()
}

// printVersionUsage prints usage documentation for 'faradaiwire version'.
func printVersionUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire version [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Prints the FaradAiWire binary version information.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  -h, --help\tShow help for version command")
	w.Flush()
}

// printExportUsage prints usage documentation for 'faradaiwire export'.
func printExportUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  faradaiwire export --profile <name> --client <client> [flags]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Exports a Security Profile's Tool Sources into a Target Client's native MCP JSON without raw secrets or overwriting existing client configs.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  --profile <name>\tSecurity Profile name to export (required)")
	fmt.Fprintln(w, "  --client <id>\tTarget Client (claude-code, claude-desktop, cursor, cursor-workspace, windsurf, cline, roo-code, antigravity, generic)")
	fmt.Fprintln(w, "  --scope <scope>\tTarget scope (global or project)")
	fmt.Fprintln(w, "  --out <new-file>\tWrite primary MCP JSON to a new file (0600); refuses existing or protected client paths")
	fmt.Fprintln(w, "  --companion-out <file>\tWrite optional companion snippet (e.g. Claude Code settings) to a new file")
	fmt.Fprintln(w, "  --admin-url <url>\tQuery a remote Admin API (https:// required for non-loopback; uses ADMIN_API_KEY env)")
	fmt.Fprintln(w, "  --config <path>\tPath to YAML configuration file")
	fmt.Fprintln(w, "  -h, --help\tShow help for export command")
	w.Flush()
}
