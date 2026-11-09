package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/mcpconfig"
)

type adoptOptions struct {
	rollback     bool
	dryRun       bool
	yes          bool
	backupDir    string
	protocolsDir string
	agentsDir    string
}

// executeAdopt discovers MCP servers across Claude Desktop, Cursor, and Windsurf,
// prompts the user for confirmation, imports them into FaradAiWire, backs up IDE configs,
// and mutates client IDE configurations to route traffic through the FaradAiWire gateway.
func executeAdopt(opts adoptOptions, in io.Reader, out io.Writer) int {
	adapters := []mcpconfig.ClientAdapter{
		mcpconfig.NewClaudeDesktopAdapter(),
		mcpconfig.NewCursorAdapter(),
		mcpconfig.NewWindsurfAdapter(),
	}
	return executeAdoptWithAdapters(opts, in, out, adapters)
}

func executeAdoptWithAdapters(opts adoptOptions, in io.Reader, out io.Writer, adapters []mcpconfig.ClientAdapter) int {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
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

		for _, adapter := range adapters {
			clientID := adapter.ID()
			if backupMgr.HasBackup(clientID) {
				cfgPath, err := adapter.ConfigPath()
				if err != nil {
					fmt.Fprintf(out, "[!] Warning: Cannot resolve config path for %s: %v\n", adapter.DisplayName(), err)
					continue
				}

				if err := backupMgr.RestoreBackup(clientID, cfgPath); err != nil {
					fmt.Fprintf(out, "[X] Failed to restore %s: %v\n", adapter.DisplayName(), err)
				} else {
					fmt.Fprintf(out, "[✓] Restored %s configuration from backup\n", adapter.DisplayName())
					restoredCount++
				}
			}
		}

		if restoredCount == 0 {
			fmt.Fprintln(out, "No active client backups found to restore.")
			return 0
		}

		fmt.Fprintln(out, "\n🎉 Rollback complete. Original client configurations have been restored.")
		return 0
	}

	// --- ADOPTION WORKFLOW ---
	fmt.Fprintln(out, "\nFaradAiWire - Zero-Trust MCP Adoption Wizard")
	fmt.Fprintln(out, "===========================================")
	fmt.Fprintln(out, "Scanning developer environment for installed MCP clients...")

	type clientCandidate struct {
		adapter mcpconfig.ClientAdapter
		servers []mcpconfig.DiscoveredServer
	}

	var candidates []clientCandidate
	totalServers := 0

	for _, adapter := range adapters {
		if !adapter.Detect() {
			continue
		}

		servers, err := adapter.ReadServers()
		if err != nil {
			fmt.Fprintf(out, "[!] Warning: Error reading %s config: %v\n", adapter.DisplayName(), err)
			continue
		}

		if len(servers) > 0 {
			candidates = append(candidates, clientCandidate{
				adapter: adapter,
				servers: servers,
			})
			totalServers += len(servers)
		}
	}

	if totalServers == 0 {
		fmt.Fprintln(out, "\nNo MCP servers detected across Claude Desktop, Cursor, or Windsurf.")
		fmt.Fprintln(out, "To manually connect an agent, run: faradaiwire run")
		return 0
	}

	fmt.Fprintf(out, "\nDiscovered %d MCP server(s) across %d client(s):\n", totalServers, len(candidates))
	counter := 1

	for _, c := range candidates {
		fmt.Fprintf(out, "\n📁 %s:\n", c.adapter.DisplayName())
		for _, s := range c.servers {
			match := mcpconfig.MatchPreset(s, nil)
			typeLabel := "Stdio"
			if s.URL != "" {
				typeLabel = "SSE"
			}

			fmt.Fprintf(out, "  [%d] %s (%s)\n", counter, s.Name, typeLabel)
			if s.Command != "" {
				fmt.Fprintf(out, "      ↳ Command : %s %s\n", s.Command, strings.Join(s.Args, " "))
			} else if s.URL != "" {
				fmt.Fprintf(out, "      ↳ URL     : %s\n", s.URL)
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
			fmt.Fprintf(out, "  • Backup %s to %s\n", p, backupMgr.BackupPath(c.adapter.ID()))
			fmt.Fprintf(out, "  • Register %d Tool Source(s) in %s\n", len(c.servers), opts.protocolsDir)
			fmt.Fprintf(out, "  • Initialize Security Profile in %s/%s\n", opts.agentsDir, c.adapter.ID())
			fmt.Fprintf(out, "  • Mutate %s to route through FaradAiWire Gateway\n", p)
		}
		fmt.Fprintln(out, "\n[DRY-RUN] No files were modified on disk.")
		return 0
	}

	// Interactive user confirmation
	if !opts.yes {
		fmt.Fprintf(out, "Import and protect all %d discovered MCP servers? [Y/n]: ", totalServers)
		scanner := bufio.NewScanner(in)
		if scanner.Scan() {
			ans := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if ans != "" && ans != "y" && ans != "yes" {
				fmt.Fprintln(out, "Adoption cancelled by user.")
				return 0
			}
		}
	}

	fmt.Fprintln(out, "\nExecuting adoption and security shielding...")

	for _, c := range candidates {
		cfgPath, err := c.adapter.ConfigPath()
		if err != nil {
			fmt.Fprintf(out, "[X] Error resolving path for %s: %v\n", c.adapter.DisplayName(), err)
			continue
		}

		// 1. Create pristine application-level backup
		backupPath, err := backupMgr.CreateBackup(c.adapter.ID(), cfgPath)
		if err != nil {
			fmt.Fprintf(out, "[X] Failed to backup %s: %v\n", c.adapter.DisplayName(), err)
			continue
		}
		fmt.Fprintf(out, "[✓] Created backup: %s\n", backupPath)

		// 2. Persist Tool Sources and Security Profile
		profileName := string(c.adapter.ID())
		if err := mcpconfig.PersistAdoptedProtocols(profileName, c.servers, nil, opts.protocolsDir, opts.agentsDir); err != nil {
			fmt.Fprintf(out, "[X] Failed to persist protocols for %s: %v\n", c.adapter.DisplayName(), err)
			continue
		}
		fmt.Fprintf(out, "[✓] Registered %d Tool Source(s) and Security Profile '%s'\n", len(c.servers), profileName)

		// 3. Probe upstream tools and generate tools_manifest.json
		ctx := context.Background()
		fmt.Fprintf(out, "    ↳ Introspecting upstream tool schemas for %s...\n", c.adapter.DisplayName())
		probeRes, _ := mcpconfig.ProbeAndCompileManifest(ctx, profileName, c.servers, opts.agentsDir, 4*time.Second)
		activeCount := 0
		for _, pr := range probeRes {
			if pr.Success {
				activeCount += pr.ToolCount
			}
		}
		fmt.Fprintf(out, "[✓] Compiled tools manifest (%d active tools ready)\n", activeCount)

		// 4. Mutate client IDE config to connect via FaradAiWire
		var serverNames []string
		for _, s := range c.servers {
			serverNames = append(serverNames, s.Name)
		}

		if err := c.adapter.ApplyGatewayConfig(profileName, serverNames); err != nil {
			fmt.Fprintf(out, "[X] Failed to update %s config: %v (Restoring backup...)\n", c.adapter.DisplayName(), err)
			_ = backupMgr.RestoreBackup(c.adapter.ID(), cfgPath)
			continue
		}
		fmt.Fprintf(out, "[✓] Successfully updated %s to route via FaradAiWire Gateway\n", c.adapter.DisplayName())
	}

	fmt.Fprintln(out, "\n🎉 FaradAiWire adoption completed successfully!")
	fmt.Fprintln(out, "All client tool calls are now shielded by FaradAiWire's Zero-Trust guardrails.")
	fmt.Fprintln(out, "\n💡 Useful commands:")
	fmt.Fprintln(out, "  • View live traffic and audit logs : faradaiwire run (then open http://127.0.0.1:8095)")
	fmt.Fprintln(out, "  • Revert back to original configs  : faradaiwire adopt --rollback")
	return 0
}
