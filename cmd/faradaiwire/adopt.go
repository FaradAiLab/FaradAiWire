package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/db/duckdb"
	"github.com/FaradAiLab/FaradAiWire/internal/filter/schema"
	"github.com/FaradAiLab/FaradAiWire/internal/mcpconfig"
	"github.com/FaradAiLab/FaradAiWire/internal/protocol"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

type adoptOptions struct {
	rollback     bool
	dryRun       bool
	yes          bool
	workspace    bool
	servers      string
	probeTimeout time.Duration
	backupDir    string
	protocolsDir string
	agentsDir    string
	configPath   string
	keysPath     string
	dbPath       string
}

var adoptAdminHTTPClient = &http.Client{
	Timeout:       1500 * time.Millisecond,
	CheckRedirect: blockRedirects,
}

// executeAdopt discovers MCP servers across Antigravity, Claude Desktop, Cursor,
// Windsurf, Claude Code, Cline, and Roo Code, prompts the user for confirmation,
// imports them into FaradAiWire, backs up IDE configs, and mutates client configurations
// to route traffic through the FaradAiWire gateway.
func executeAdopt(opts adoptOptions, in io.Reader, out io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	adapters := []mcpconfig.ClientAdapter{
		mcpconfig.NewAntigravityAdapter(),
		mcpconfig.NewClaudeDesktopAdapter(),
		mcpconfig.NewCursorAdapter(),
		mcpconfig.NewWindsurfAdapter(),
		mcpconfig.NewClaudeCodeAdapter(),
		mcpconfig.NewClineAdapter(),
		mcpconfig.NewRooCodeAdapter(),
	}
	if opts.rollback {
		// Rollback discovers both global and workspace-local backups if run inside a workspace.
		adapters = append(adapters, mcpconfig.NewCursorWorkspaceAdapter())
	} else if opts.workspace {
		fmt.Fprintln(out, "[!] Warning: --workspace enabled; workspace-local ./.cursor/mcp.json may define commands controlled by this repository. Review all discovered commands carefully before confirming.")
		adapters = append(adapters, mcpconfig.NewCursorWorkspaceAdapter())
	}
	return executeAdoptWithAdapters(opts, in, out, adapters)
}

func profileNameForAdapter(a mcpconfig.ClientAdapter) string {
	if a.ID() == mcpconfig.ClientCursorWorkspace || (a.ID() == mcpconfig.ClientCursor && a.DisplayName() == "Cursor (Workspace)") {
		return "cursor-workspace"
	}
	return string(a.ID())
}

func parseServerFilter(raw string) map[string]struct{} {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	allowed := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			allowed[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func resolveAdoptProbeTimeout(explicit time.Duration, cfg *config.Config, dbPath string) time.Duration {
	if explicit > 0 {
		return explicit
	}
	fallback := time.Duration(settings.DefaultOperationalSettings().Timeouts.ProbeTimeoutSec) * time.Second
	if fallback <= 0 {
		fallback = 5 * time.Second
	}

	// 1. Query running gateway Admin API /admin/settings (loopback standalone admin port)
	if timeout, ok := queryAdminProbeTimeout(cfg); ok {
		return timeout
	}

	// 2. Fallback to offline DuckDB system_settings when gateway is stopped
	if dbPath != "" {
		if fi, statErr := os.Stat(dbPath); statErr == nil && !fi.IsDir() {
			mgr, err := duckdb.NewManager(duckdb.Config{DBPath: dbPath})
			if err == nil {
				defer mgr.Close()
				store := settings.NewDuckDBStore(mgr.DB())
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				val, exists, getErr := store.Get(ctx, "timeouts.probe_timeout_sec")
				cancel()
				if getErr == nil && exists {
					if sec, convErr := strconv.Atoi(strings.TrimSpace(val)); convErr == nil && sec > 0 {
						return time.Duration(sec) * time.Second
					}
				}
			}
		}
	}

	return fallback
}

func resolveAdminEndpointHost(cfg *config.Config) string {
	if cfg == nil {
		return "127.0.0.1"
	}
	host := normalizeGatewayHost(cfg.GetAdminHost())
	if cfg.IsStandalone() && !isLoopbackHost(host) {
		return "127.0.0.1"
	}
	return host
}

func adminScheme(cfg *config.Config) string {
	if cfg != nil && cfg.AdminTLS.Enabled {
		return "https"
	}
	return "http"
}

func resolveAdminBearerToken() string {
	for _, envVar := range []string{"ADMIN_API_KEY", "FARADAI_WIRE_ADMIN_TOKEN"} {
		if tok := strings.TrimSpace(os.Getenv(envVar)); tok != "" {
			return tok
		}
	}
	return ""
}

// attachAdminBearerAuth attaches the configured admin Bearer token to req only when
// req targets a loopback host or uses an encrypted https:// scheme.
func attachAdminBearerAuth(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	useTLS := strings.EqualFold(req.URL.Scheme, "https")
	host := req.URL.Hostname()
	if adminKey := resolveAdminBearerToken(); adminKey != "" && (isLoopbackHost(host) || useTLS) {
		req.Header.Set("Authorization", "Bearer "+adminKey)
	}
}

func queryAdminProbeTimeout(cfg *config.Config) (time.Duration, bool) {
	if cfg == nil {
		return 0, false
	}
	host := resolveAdminEndpointHost(cfg)
	adminPort := cfg.GetAdminPort()
	scheme := adminScheme(cfg)
	settingsURL := fmt.Sprintf("%s://%s/admin/settings", scheme, net.JoinHostPort(host, strconv.Itoa(adminPort)))
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, settingsURL, nil)
	if err != nil {
		return 0, false
	}
	attachAdminBearerAuth(req)
	resp, reqErr := adoptAdminHTTPClient.Do(req)
	if reqErr != nil || resp == nil {
		return 0, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return 0, false
	}

	var payload struct {
		Settings []struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		} `json:"settings"`
	}
	if decErr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); decErr != nil {
		return 0, false
	}
	for _, item := range payload.Settings {
		if item.Key == "timeouts.probe_timeout_sec" {
			if sec := parsePositiveSeconds(item.Value); sec > 0 {
				return time.Duration(sec) * time.Second, true
			}
		}
	}
	return 0, false
}

func parsePositiveSeconds(v any) int {
	switch tv := v.(type) {
	case float64:
		if tv > 0 {
			return int(tv)
		}
	case int:
		if tv > 0 {
			return tv
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(tv)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func isDuckDBLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "lock") || strings.Contains(msg, "conflicting")
}

func ensureProfileAPIKey(ks *auth.FileKeyStore, profileName string) (created bool, prefix string, err error) {
	if ks == nil {
		return false, "", nil
	}
	for _, k := range ks.ListKeys() {
		if !k.Revoked && k.RawKey != "" && strings.EqualFold(k.AgentName, profileName) {
			return false, k.Prefix, nil
		}
	}
	_, rec, genErr := ks.GenerateKey("adopt-"+profileName, "Agent", profileName)
	if genErr != nil {
		return false, "", fmt.Errorf("generate scoped key for %q: %w", profileName, genErr)
	}
	return true, rec.Prefix, nil
}

func executeAdoptWithAdapters(opts adoptOptions, in io.Reader, out io.Writer, adapters []mcpconfig.ClientAdapter) int {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if opts.probeTimeout < 0 {
		fmt.Fprintf(out, "Error: --probe-timeout cannot be negative (%v)\n", opts.probeTimeout)
		return 1
	}

	defaultDataDir := config.DefaultFaradAiWireDir()
	defaultProtocolsDir := filepath.Join(defaultDataDir, "protocols")
	defaultAgentsDir := filepath.Join(defaultDataDir, "agents")
	if strings.TrimSpace(opts.protocolsDir) == "" {
		opts.protocolsDir = defaultProtocolsDir
	}
	if strings.TrimSpace(opts.agentsDir) == "" {
		opts.agentsDir = defaultAgentsDir
	}

	backupMgr, err := mcpconfig.NewBackupManager(opts.backupDir)
	if err != nil {
		fmt.Fprintf(out, "Error: Failed to initialize backup manager: %v\n", err)
		return 1
	}

	// --- ROLLBACK WORKFLOW ---
	if opts.rollback {
		fmt.Fprintln(out, "\nFaradAiWire MCP Rollback")
		fmt.Fprintln(out, "=======================")
		restoredCount := 0
		failedCount := 0

		for _, adapter := range adapters {
			clientID := adapter.ID()
			cfgPath, err := adapter.ConfigPath()
			if err != nil {
				if backupMgr.HasBackup(clientID) {
					fmt.Fprintf(out, "[!] Warning: Cannot resolve config path for %s: %v\n", adapter.DisplayName(), err)
					failedCount++
				}
				continue
			}

			if backupMgr.HasBackupForConfig(clientID, cfgPath) {
				if err := backupMgr.RestoreBackup(clientID, cfgPath); err != nil {
					fmt.Fprintf(out, "[X] Failed to restore %s: %v\n", adapter.DisplayName(), err)
					failedCount++
				} else {
					fmt.Fprintf(out, "[✓] Restored %s configuration from backup\n", adapter.DisplayName())
					restoredCount++
				}
			}
		}

		if failedCount > 0 {
			fmt.Fprintf(out, "\n[X] Rollback encountered %d error(s) (%d restored).\n", failedCount, restoredCount)
			return 1
		}
		if restoredCount == 0 {
			fmt.Fprintln(out, "No active client backups found to restore.")
			return 0
		}

		fmt.Fprintln(out, "\n🎉 Rollback complete. Original client configurations have been restored.")
		return 0
	}

	// Load existing config without mutating disk when only scanning/dry-run
	var cfg *config.Config
	var cfgPathForLoad string
	if strings.TrimSpace(opts.configPath) != "" {
		cfgPathForLoad = opts.configPath
	} else {
		candidateCfg := filepath.Join(defaultDataDir, "config.yaml")
		if _, statErr := os.Stat(candidateCfg); statErr == nil {
			cfgPathForLoad = candidateCfg
		}
	}
	if cfgPathForLoad != "" {
		loaded, loadErr := config.NewYAMLConfigProvider(cfgPathForLoad).Load()
		if loadErr != nil {
			if strings.TrimSpace(opts.configPath) != "" {
				fmt.Fprintf(out, "Error: Failed to load config file %q: %v\n", opts.configPath, loadErr)
				return 1
			}
		} else {
			cfg = loaded
		}
	}
	if cfg == nil {
		cfg = &config.Config{}
	}

	usingDefaultAgentsDir := filepath.Clean(opts.agentsDir) == filepath.Clean(defaultAgentsDir)
	keysPath := opts.keysPath
	if keysPath == "" {
		if usingDefaultAgentsDir {
			keysPath = cfg.GetAPIKeysPath()
		} else {
			keysPath = filepath.Join(filepath.Dir(opts.agentsDir), "keys", "api_keys.json")
		}
	}
	dbPath := opts.dbPath
	if dbPath == "" {
		if usingDefaultAgentsDir {
			dbPath = cfg.GetTelemetryDBPath()
		} else {
			dbPath = filepath.Join(filepath.Dir(opts.agentsDir), "data", "wire.duckdb")
		}
	}

	// --- ADOPTION WORKFLOW ---
	fmt.Fprintln(out, "\nFaradAiWire - Zero-Trust MCP Adoption Wizard")
	fmt.Fprintln(out, "===========================================")
	fmt.Fprintln(out, "Scanning developer environment for installed MCP clients...")

	serverFilter := parseServerFilter(opts.servers)
	ssrfOpts := transport.OptionsFromConfig(cfg.Security.SSRFProtection)

	type clientCandidate struct {
		adapter mcpconfig.ClientAdapter
		profile string
		servers []mcpconfig.DiscoveredServer
	}

	var candidates []clientCandidate
	totalServers := 0
	hasRemoteURLs := false
	blockedURLCount := 0

	for _, adapter := range adapters {
		if !adapter.Detect() {
			continue
		}

		servers, err := adapter.ReadServers()
		if err != nil {
			fmt.Fprintf(out, "[!] Warning: Error reading %s config: %v\n", adapter.DisplayName(), err)
			continue
		}

		filtered := make([]mcpconfig.DiscoveredServer, 0, len(servers))
		for _, s := range servers {
			if serverFilter != nil {
				if _, ok := serverFilter[strings.ToLower(s.Name)]; !ok {
					continue
				}
			}
			if s.URL != "" {
				if urlErr := transport.ValidateURL(s.URL, ssrfOpts); urlErr != nil {
					blockedURLCount++
					fmt.Fprintf(out, "[X] Blocked unsafe MCP URL for %s '%s' (%s): %v\n",
						adapter.DisplayName(), s.Name, protocol.RedactURLCredentials(s.URL), urlErr)
					continue
				}
				hasRemoteURLs = true
			}
			filtered = append(filtered, s)
		}

		if len(filtered) > 0 {
			candidates = append(candidates, clientCandidate{
				adapter: adapter,
				profile: profileNameForAdapter(adapter),
				servers: filtered,
			})
			totalServers += len(filtered)
		}
	}

	if blockedURLCount > 0 && !opts.dryRun {
		fmt.Fprintf(out, "\n[X] Adoption aborted: %d discovered remote MCP URL(s) violated SSRF safety policy.\n", blockedURLCount)
		return 1
	}

	if totalServers == 0 {
		fmt.Fprintln(out, "\nNo MCP servers detected across supported AI clients.")
		fmt.Fprintln(out, "To manually connect an agent, run: faradaiwire run")
		return 0
	}

	probeTimeout := resolveAdoptProbeTimeout(opts.probeTimeout, cfg, dbPath)
	presets := protocol.GetPresets()

	fmt.Fprintf(out, "\nDiscovered %d MCP server(s) across %d client(s) (probe timeout: %s):\n", totalServers, len(candidates), probeTimeout)
	counter := 1

	for _, c := range candidates {
		fmt.Fprintf(out, "\n📁 %s:\n", c.adapter.DisplayName())
		for _, s := range c.servers {
			match := mcpconfig.MatchPreset(s, presets)
			typeLabel := "Stdio"
			if s.URL != "" {
				typeLabel = "SSE/HTTP"
			}

			fmt.Fprintf(out, "  [%d] %s (%s)\n", counter, s.Name, typeLabel)
			if s.Command != "" {
				fmt.Fprintf(out, "      ↳ Command : %s %s\n", s.Command, strings.Join(s.Args, " "))
			} else if s.URL != "" {
				fmt.Fprintf(out, "      ↳ URL     : %s\n", protocol.RedactURLCredentials(s.URL))
			}

			if match.Preset != nil {
				fmt.Fprintf(out, "      ↳ Preset  : %s\n", match.Preset.Name)
				if len(match.RecommendedDLP) > 0 {
					fmt.Fprintf(out, "      ↳ Policy  : Recommended %s\n", match.RecommendedDLP[0])
				}
			} else {
				fmt.Fprintln(out, "      ↳ Type    : Custom Tool Source")
			}
			counter++
		}
	}

	fmt.Fprintln(out)

	if opts.dryRun {
		fmt.Fprintln(out, "[DRY-RUN] Planned changes:")
		for _, c := range candidates {
			p, _ := c.adapter.ConfigPath()
			fmt.Fprintf(out, "  • Backup %s to %s\n", p, backupMgr.BackupPathForConfig(c.adapter.ID(), p))
			fmt.Fprintf(out, "  • Register %d Tool Source(s) in %s\n", len(c.servers), opts.protocolsDir)
			fmt.Fprintf(out, "  • Initialize Security Profile '%s' and DLP/HITL rules in %s/%s\n", c.profile, opts.agentsDir, c.profile)
			fmt.Fprintf(out, "  • Ensure scoped local API key in %s\n", keysPath)
			fmt.Fprintf(out, "  • Mutate %s to route through FaradAiWire Gateway\n", p)
		}
		fmt.Fprintln(out, "\n[DRY-RUN] No files were modified on disk.")
		return 0
	}

	// Interactive user confirmation (fail-closed on EOF/error; require explicit 'y' when remote URLs are present)
	if !opts.yes {
		if hasRemoteURLs {
			fmt.Fprintln(out, "[!] Remote HTTP/SSE MCP endpoint(s) detected. Proxied MCP payloads will leave this host.")
			fmt.Fprintf(out, "Confirm importing remote URL(s) and protecting all %d MCP servers? [y/N]: ", totalServers)
		} else {
			fmt.Fprintf(out, "Import and protect all %d discovered MCP servers? [Y/n]: ", totalServers)
		}
		scanner := bufio.NewScanner(in)
		if !scanner.Scan() {
			if scanErr := scanner.Err(); scanErr != nil {
				fmt.Fprintf(out, "\nAdoption aborted: failed to read confirmation input: %v\n", scanErr)
			} else {
				fmt.Fprintln(out, "\nAdoption aborted: interactive confirmation required (pass --yes for non-interactive runs).")
			}
			return 1
		}
		ans := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if hasRemoteURLs {
			if ans != "y" && ans != "yes" {
				fmt.Fprintln(out, "Adoption cancelled by user.")
				return 0
			}
		} else {
			if ans != "" && ans != "y" && ans != "yes" {
				fmt.Fprintln(out, "Adoption cancelled by user.")
				return 0
			}
		}
	}

	// Ensure runtime config.yaml exists only when writing to default FaradAiWire location or explicit -config
	runtimeConfigPath := strings.TrimSpace(opts.configPath)
	if runtimeConfigPath == "" && usingDefaultAgentsDir {
		if ensuredCfg, cfgErr := config.EnsureDefaultRuntimeConfig(); cfgErr != nil {
			fmt.Fprintf(out, "[!] Warning: could not ensure default config.yaml: %v\n", cfgErr)
		} else {
			runtimeConfigPath = ensuredCfg
		}
	}

	protoStore, err := protocol.NewFSStore(opts.protocolsDir)
	if err != nil {
		fmt.Fprintf(out, "Error: Failed to initialize protocol store in %s: %v\n", opts.protocolsDir, err)
		return 1
	}
	_ = protoStore.EnsureGitIgnore(filepath.Dir(opts.protocolsDir))

	keyStore, keyErr := auth.NewFileKeyStore(keysPath)
	if keyErr != nil {
		fmt.Fprintf(out, "Error: Failed to initialize local API key store (%s): %v\n", keysPath, keyErr)
		return 1
	}

	var schemaStore *schema.DuckDBSchemaStore
	if dbPath != "" {
		var sErr error
		schemaStore, sErr = schema.OpenDuckDBSchemaStore(dbPath)
		if sErr != nil {
			if isDuckDBLockError(sErr) {
				fmt.Fprintln(out, "[!] Notice: DuckDB database is currently locked by the running gateway; tool schema baselines will be indexed when the gateway reloads.")
			} else {
				fmt.Fprintf(out, "[!] Warning: Unable to open DuckDB schema store (%s): %v\n", dbPath, sErr)
			}
			schemaStore = nil
		} else {
			defer func() { _ = schemaStore.Close() }()
		}
	}

	fmt.Fprintln(out, "\nExecuting adoption and security shielding...")

	succeededCount := 0
	failedCount := 0

	for _, c := range candidates {
		cfgPath, err := c.adapter.ConfigPath()
		if err != nil {
			fmt.Fprintf(out, "[X] Error resolving path for %s: %v\n", c.adapter.DisplayName(), err)
			failedCount++
			continue
		}

		// 1. Create pristine application-level backup keyed by client + canonical path
		backupPath, err := backupMgr.CreateBackup(c.adapter.ID(), cfgPath)
		if err != nil {
			fmt.Fprintf(out, "[X] Failed to backup %s: %v\n", c.adapter.DisplayName(), err)
			failedCount++
			continue
		}
		fmt.Fprintf(out, "[✓] Created backup: %s\n", backupPath)

		// 2. Persist Tool Sources via FSStore and Security Profile
		if err := mcpconfig.PersistAdoptedProtocols(c.profile, c.servers, protoStore, opts.protocolsDir, opts.agentsDir); err != nil {
			fmt.Fprintf(out, "[X] Failed to persist protocols for %s: %v\n", c.adapter.DisplayName(), err)
			failedCount++
			continue
		}
		fmt.Fprintf(out, "[✓] Registered %d Tool Source(s) and Security Profile '%s'\n", len(c.servers), c.profile)

		// 3. Probe upstream tools and generate tools_manifest.json
		ctx := context.Background()
		fmt.Fprintf(out, "    ↳ Introspecting upstream tool schemas for %s (timeout: %s)...\n", c.adapter.DisplayName(), probeTimeout)
		probeRes, probeErr := mcpconfig.ProbeAndCompileManifest(ctx, c.profile, c.servers, opts.agentsDir, probeTimeout)
		if probeErr != nil {
			fmt.Fprintf(out, "    [!] Notice compiling manifest: %v\n", probeErr)
		}
		activeCount := 0
		for _, pr := range probeRes {
			if pr.Success {
				activeCount += pr.ToolCount
			} else if pr.Warning != "" {
				fmt.Fprintf(out, "    [!] %s: %s\n", pr.ServerName, pr.Warning)
			}
		}
		fmt.Fprintf(out, "[✓] Compiled tools manifest (%d active tools ready)\n", activeCount)

		// 4. Persist preset DLP & HITL recommendations
		recSummary, recErr := mcpconfig.PersistMatchRecommendations(c.profile, c.servers, opts.agentsDir, runtimeConfigPath)
		if recErr != nil {
			fmt.Fprintf(out, "    [!] Warning persisting preset policies for %s: %v\n", c.adapter.DisplayName(), recErr)
		} else if recSummary != nil && (recSummary.DLPPatternsAdded > 0 || recSummary.HITLGovernanceAdded > 0) {
			fmt.Fprintf(out, "[✓] Applied preset recommendations (%d DLP rule(s), %d HITL governance rule(s))\n",
				recSummary.DLPPatternsAdded, recSummary.HITLGovernanceAdded)
		}

		// 5. Seed DuckDB mcp_tool_schemas baselines when DB is accessible
		if schemaStore != nil {
			seededCount, seedErr := mcpconfig.SeedDiscoveredSchemas(ctx, c.profile, c.servers, probeRes, schemaStore)
			if seedErr != nil {
				fmt.Fprintf(out, "    [!] Warning seeding schema baselines for %s: %v\n", c.adapter.DisplayName(), seedErr)
			} else if seededCount > 0 {
				fmt.Fprintf(out, "[✓] Seeded %d tool schema baseline(s) in DuckDB\n", seededCount)
			}
		}

		// 6. Auto-provision a scoped local API key for this adopted profile (Zero-Trust ingress)
		createdKey, keyPrefix, keyProvErr := ensureProfileAPIKey(keyStore, c.profile)
		if keyProvErr != nil {
			fmt.Fprintf(out, "[X] Failed to provision local API key for '%s': %v\n", c.profile, keyProvErr)
			failedCount++
			continue
		}
		if createdKey {
			fmt.Fprintf(out, "[✓] Provisioned scoped local API key (%s...) for profile '%s'\n", keyPrefix, c.profile)
		}

		// 7. Mutate client IDE config to connect via FaradAiWire
		serverNames := make([]string, 0, len(c.servers))
		for _, s := range c.servers {
			serverNames = append(serverNames, s.Name)
		}

		if err := c.adapter.ApplyGatewayConfig(c.profile, serverNames); err != nil {
			fmt.Fprintf(out, "[X] Failed to update %s config: %v (Restoring backup...)\n", c.adapter.DisplayName(), err)
			_ = backupMgr.RestoreBackup(c.adapter.ID(), cfgPath)
			failedCount++
			continue
		}
		fmt.Fprintf(out, "[✓] Successfully updated %s to route via FaradAiWire Gateway\n", c.adapter.DisplayName())
		succeededCount++
	}

	if failedCount > 0 || succeededCount == 0 {
		fmt.Fprintf(out, "\n[X] Adoption finished with errors (%d succeeded, %d failed).\n", succeededCount, failedCount)
		return 1
	}

	fmt.Fprintln(out, "\n🎉 FaradAiWire adoption completed successfully!")
	fmt.Fprintln(out, "All client tool calls are now shielded by FaradAiWire's Zero-Trust guardrails.")
	fmt.Fprintln(out, "\n💡 Useful commands:")
	fmt.Fprintln(out, "  • View live traffic and audit logs : faradaiwire run (then open http://127.0.0.1:8095)")
	fmt.Fprintln(out, "  • Revert back to original configs  : faradaiwire adopt --rollback")
	return 0
}
