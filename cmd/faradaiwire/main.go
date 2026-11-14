package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/gateway"
	"github.com/FaradAiLab/FaradAiWire/internal/processguard"
)

var version = config.Version

// isHelpArg returns true if the argument represents a standard help request.
func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "-help" || arg == "help"
}

// parseAuditArgs extracts target path/URL and JSON flag independently of argument ordering.
// It allocates zero heap memory on typical invocations (stack-evaluated comparisons).
func parseAuditArgs(args []string) (target string, jsonOutput bool, showHelp bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" || arg == "-help" {
			return "", false, true, nil
		}
		if arg == "help" && i == 0 && !jsonOutput {
			if _, statErr := os.Stat(arg); statErr != nil {
				return "", false, true, nil
			}
		}
		if arg == "-json" || arg == "--json" {
			jsonOutput = true
		} else if strings.HasPrefix(arg, "-") {
			return "", false, false, fmt.Errorf("unknown flag: %s", arg)
		} else if target == "" {
			target = arg
		} else {
			return "", false, false, fmt.Errorf("unexpected argument: %s", arg)
		}
	}
	return target, jsonOutput, false, nil
}

// parseGuardModelArgs extracts target model ID and optional config path independently of argument ordering.
func parseGuardModelArgs(subcmd string, args []string) (modelID string, configPath string, showHelp bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if isHelpArg(arg) {
			return "", "", true, nil
		}
		if arg == "-config" || arg == "--config" {
			if i+1 >= len(args) {
				return "", "", false, fmt.Errorf("flag needs an argument: %s", arg)
			}
			i++
			configPath = args[i]
		} else if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") {
			parts := strings.SplitN(arg, "=", 2)
			configPath = parts[1]
		} else if strings.HasPrefix(arg, "-") {
			return "", "", false, fmt.Errorf("unknown flag: %s", arg)
		} else if modelID == "" {
			modelID = arg
		} else {
			return "", "", false, fmt.Errorf("unexpected argument: %s", arg)
		}
	}
	return modelID, configPath, false, nil
}

func main() {
	code := runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

// runCLI parses arguments and dispatches commands. It accepts streams for full unit testability.
func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stderr)
		return 1
	}
	if isHelpArg(args[0]) {
		printRootUsage(stdout)
		return 0
	}

	switch args[0] {
	case "run":
		if len(args) > 1 && isHelpArg(args[1]) {
			printRunUsage(stdout)
			return 0
		}
		opts, showHelp, parseCode := parseRunFlags(args[1:], stderr)
		if showHelp {
			printRunUsage(stdout)
			return 0
		}
		if parseCode != 0 {
			return parseCode
		}
		executeRun(opts)
		return 0

	case "adopt":
		if len(args) > 1 && isHelpArg(args[1]) {
			printAdoptUsage(stdout)
			return 0
		}
		fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.Usage = func() { printAdoptUsage(stderr) }
		defaultDataDir := config.DefaultFaradAiWireDir()
		cfgPath := fs.String("config", "", "Path to YAML configuration file")
		rollback := fs.Bool("rollback", false, "Revert client configurations back to pristine pre-adoption backups")
		dryRun := fs.Bool("dry-run", false, "Preview planned adoption changes without mutating files on disk")
		yes := fs.Bool("yes", false, "Automatically accept all adoption prompts without interactive confirmation")
		fs.BoolVar(yes, "y", false, "Alias for --yes")
		workspace := fs.Bool("workspace", false, "Also scan workspace-local ./.cursor/mcp.json (confirm untrusted workspace commands carefully)")
		servers := fs.String("servers", "", "Comma-separated list of MCP server names to adopt (default: all discovered)")
		probeTimeout := fs.Duration("probe-timeout", 0, "Override per-server MCP tool discovery probe timeout (e.g. 10s)")
		backupDir := fs.String("backup-dir", "", "Custom directory to store client configuration backups")
		protocolsDir := fs.String("protocols-dir", filepath.Join(defaultDataDir, "protocols"), "Directory to store imported Tool Sources")
		agentsDir := fs.String("agents-dir", filepath.Join(defaultDataDir, "agents"), "Directory to store client Security Profiles")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 1
		}
		return executeAdopt(adoptOptions{
			configPath:   *cfgPath,
			rollback:     *rollback,
			dryRun:       *dryRun,
			yes:          *yes,
			workspace:    *workspace,
			servers:      *servers,
			probeTimeout: *probeTimeout,
			backupDir:    *backupDir,
			protocolsDir: *protocolsDir,
			agentsDir:    *agentsDir,
		}, stdin, stdout)

	case "connect":
		if len(args) > 1 && isHelpArg(args[1]) {
			printConnectUsage(stdout)
			return 0
		}
		fs := flag.NewFlagSet("connect", flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.Usage = func() { printConnectUsage(stderr) }
		profile := fs.String("profile", "default", "Target Security Profile name to route traffic through")
		host := fs.String("host", "127.0.0.1", "Gateway ingress host address")
		port := fs.Int("port", 8090, "Gateway ingress port")
		token := fs.String("token", "", "Optional API bearer token")
		noSpawn := fs.Bool("no-spawn", false, "Do not auto-spawn the background daemon if offline")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 1
		}
		return executeConnect(*profile, *host, *port, *token, *noSpawn, stdin, stdout)

	case "doctor":
		if len(args) > 1 && isHelpArg(args[1]) {
			printDoctorUsage(stdout)
			return 0
		}
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.Usage = func() { printDoctorUsage(stderr) }
		cfgPath := fs.String("config", "", "Path to YAML configuration file")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 1
		}
		return executeDoctor(*cfgPath, stdout)

	case "audit":
		target, jsonOutput, showHelp, err := parseAuditArgs(args[1:])
		if showHelp {
			printAuditUsage(stdout)
			return 0
		}
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			printAuditUsage(stderr)
			return 1
		}
		if target == "" {
			fmt.Fprintln(stderr, "Error: audit command requires a path or URL. Usage: faradaiwire audit <path|url> [--json]")
			return 1
		}
		return executeAudit(target, jsonOutput, stdout)

	case "guard":
		if len(args) < 2 {
			printGuardUsageTo(stderr)
			return 1
		}
		if isHelpArg(args[1]) {
			printGuardUsageTo(stdout)
			return 0
		}
		switch args[1] {
		case "list":
			if len(args) > 2 && isHelpArg(args[2]) {
				printGuardListUsage(stdout)
				return 0
			}
			fs := flag.NewFlagSet("guard list", flag.ContinueOnError)
			fs.SetOutput(stderr)
			fs.Usage = func() { printGuardListUsage(stderr) }
			cfgPath := fs.String("config", "", "Path to YAML configuration file")
			if err := fs.Parse(args[2:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				return 1
			}
			return executeGuardList(*cfgPath, stdout)

		case "status":
			if len(args) > 2 && isHelpArg(args[2]) {
				printGuardStatusUsage(stdout)
				return 0
			}
			fs := flag.NewFlagSet("guard status", flag.ContinueOnError)
			fs.SetOutput(stderr)
			fs.Usage = func() { printGuardStatusUsage(stderr) }
			cfgPath := fs.String("config", "", "Path to YAML configuration file")
			if err := fs.Parse(args[2:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				return 1
			}
			return executeGuardStatus(*cfgPath, stdout)

		case "install":
			modelID, cfgPath, showHelp, err := parseGuardModelArgs("install", args[2:])
			if showHelp {
				printGuardInstallUsage(stdout)
				return 0
			}
			if err != nil {
				fmt.Fprintf(stderr, "Error: %v\n", err)
				printGuardInstallUsage(stderr)
				return 1
			}
			if modelID == "" {
				fmt.Fprintln(stderr, "Error: install command requires a model ID. Usage: faradaiwire guard install <id> [--config <path>]")
				return 1
			}
			return executeGuardInstall(cfgPath, modelID, stdout)

		case "uninstall":
			modelID, cfgPath, showHelp, err := parseGuardModelArgs("uninstall", args[2:])
			if showHelp {
				printGuardUninstallUsage(stdout)
				return 0
			}
			if err != nil {
				fmt.Fprintf(stderr, "Error: %v\n", err)
				printGuardUninstallUsage(stderr)
				return 1
			}
			if modelID == "" {
				fmt.Fprintln(stderr, "Error: uninstall command requires a model ID. Usage: faradaiwire guard uninstall <id> [--config <path>]")
				return 1
			}
			return executeGuardUninstall(cfgPath, modelID, stdout)

		default:
			fmt.Fprintf(stderr, "Unknown guard subcommand: %s\n\n", args[1])
			printGuardUsageTo(stderr)
			return 1
		}

	case "version":
		if len(args) > 1 && isHelpArg(args[1]) {
			printVersionUsage(stdout)
			return 0
		}
		fmt.Fprintf(stdout, "FaradAiWire Security Gateway %s\n", version)
		return 0

	default:
		fmt.Fprintf(stderr, "Unknown subcommand: %s\n\n", args[0])
		printRootUsage(stderr)
		return 1
	}
}

func printUsage() {
	printRootUsage(os.Stdout)
}

type runOptions struct {
	configPath string
	standalone bool
	host       string
	port       int
	adminHost  string
	adminPort  int
}

func parseRunFlags(args []string, stderr io.Writer) (runOptions, bool, int) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printRunUsage(stderr) }
	cfgPath := fs.String("config", "", "Path to YAML configuration file")
	standalone := fs.Bool("standalone", false, "Force offline-first standalone mode")
	host := fs.String("host", "", "Host address to bind HTTP listeners to")
	port := fs.Int("port", 0, "Ingress port to listen on")
	adminHost := fs.String("admin-host", "", "Host address to bind Admin HTTP console listener to")
	adminPort := fs.Int("admin-port", 0, "Admin console port to listen on")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runOptions{}, true, 0
		}
		return runOptions{}, false, 1
	}
	return runOptions{
		configPath: *cfgPath,
		standalone: *standalone,
		host:       *host,
		port:       *port,
		adminHost:  *adminHost,
		adminPort:  *adminPort,
	}, false, 0
}

func applyRunOverrides(cfg *config.Config, opts runOptions) {
	if opts.standalone {
		cfg.RuntimeMode = config.RuntimeModeStandalone
	}
	if strings.TrimSpace(opts.host) != "" {
		cfg.ListenHost = strings.TrimSpace(opts.host)
	}
	if opts.port > 0 {
		cfg.ListenPort = opts.port
	}
	if strings.TrimSpace(opts.adminHost) != "" {
		cfg.AdminHost = strings.TrimSpace(opts.adminHost)
	}
	if opts.adminPort > 0 {
		cfg.AdminPort = opts.adminPort
	}
}

func executeRun(opts runOptions) {
	if code := runGatewayDaemon(opts); code != 0 {
		os.Exit(code)
	}
}

func runGatewayDaemon(opts runOptions) int {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	provider := config.NewYAMLConfigProvider(opts.configPath)
	cfg, err := provider.Load()
	if err != nil {
		slog.Error("Configuration load failed", slog.String("error", err.Error()))
		return 1
	}

	applyRunOverrides(cfg, opts)

	if isInteractiveTerminal() {
		printStartupBanner(cfg, os.Stdout)
	}

	slog.Info("Starting FaradAiWire",
		slog.String("mode", cfg.GetRuntimeMode()),
		slog.String("host", cfg.GetListenHost()),
		slog.Int("port", cfg.GetListenPort()),
		slog.String("admin_host", cfg.GetAdminHost()),
		slog.Int("admin_port", cfg.GetAdminPort()),
		slog.String("config_path", cfg.ConfigPath),
		slog.Bool("zero_egress", cfg.IsStandalone()),
	)

	// Acquire single-instance process lock to prevent concurrent daemon collisions
	lockDir := filepath.Dir(cfg.ConfigPath)
	if lockDir == "" {
		lockDir = "."
	}
	lockPath := filepath.Join(lockDir, ".faradaiwire.lock")
	guard := processguard.New(lockPath)
	if err := guard.Acquire(); err != nil {
		slog.Error("Startup aborted: single-instance lock acquisition failed", slog.String("error", err.Error()))
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer func() {
		if err := guard.Release(); err != nil {
			slog.Warn("Failed to release process lock cleanly", slog.String("error", err.Error()))
		}
	}()

	server, err := gateway.NewServer(cfg, provider)
	if err != nil {
		slog.Error("Server initialization failed", slog.String("error", err.Error()))
		return 1
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.Start(serverCtx); err != nil && err != http.ErrServerClosed && err != context.Canceled {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	select {
	case sig := <-sigCh:
		slog.Info("Termination signal received, initiating graceful shutdown...", slog.String("signal", sig.String()))

		// Set up secondary signal trap for immediate forced termination
		go func() {
			if s, ok := <-sigCh; ok {
				slog.Warn("Second termination signal received, forcing immediate exit", slog.String("signal", s.String()))
				_ = guard.Release()
				os.Exit(1)
			}
		}()

		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer sCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server shutdown completed with error", slog.String("error", err.Error()))
			return 1
		}
	case err := <-serverErrCh:
		if err != nil {
			slog.Error("Gateway server terminated with error", slog.String("error", err.Error()))
			return 1
		}
	}

	slog.Info("FaradAiWire stopped cleanly.")
	return 0
}
