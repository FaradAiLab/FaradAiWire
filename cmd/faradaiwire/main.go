package main

import (
	"context"
	"flag"
	"fmt"
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

const version = config.Version

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfgPath := fs.String("config", "", "Path to YAML configuration file (autodiscovers from ./config.yaml or ~/.faradaiwire/config.yaml)")
		standalone := fs.Bool("standalone", false, "Force offline-first standalone mode (zero-egress, no cloud auth)")
		host := fs.String("host", "", "Host address to bind HTTP listeners to (default 127.0.0.1; use 0.0.0.0 for containers)")
		port := fs.Int("port", 0, "Ingress port to listen on (default 8090)")
		adminPort := fs.Int("admin-port", 0, "Admin console port to listen on (default 8095)")
		fs.Parse(os.Args[2:])
		executeRun(*cfgPath, *standalone, *host, *port, *adminPort)
	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ExitOnError)
		cfgPath := fs.String("config", "", "Path to YAML configuration file (autodiscovers from ./config.yaml or ~/.faradaiwire/config.yaml)")
		fs.Parse(os.Args[2:])
		code := executeDoctor(*cfgPath, os.Stdout)
		os.Exit(code)
	case "audit":
		if len(os.Args) < 3 {
			fmt.Println("Error: audit command requires a path or URL. Usage: faradaiwire audit <path|url> [--json]")
			os.Exit(1)
		}
		fs := flag.NewFlagSet("audit", flag.ExitOnError)
		jsonOutput := fs.Bool("json", false, "Output scan report as structured JSON")
		args := os.Args[2:]
		var target string
		var flagArgs []string
		for i := 0; i < len(args); i++ {
			if strings.HasPrefix(args[i], "-") {
				flagArgs = append(flagArgs, args[i])
			} else if target == "" {
				target = args[i]
			} else {
				flagArgs = append(flagArgs, args[i])
			}
		}
		fs.Parse(flagArgs)
		if target == "" {
			fmt.Println("Error: audit command requires a path or URL. Usage: faradaiwire audit <path|url> [--json]")
			os.Exit(1)
		}
		code := executeAudit(target, *jsonOutput, os.Stdout)
		os.Exit(code)
	case "guard":
		if len(os.Args) < 3 {
			printGuardUsage()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "list":
			fs := flag.NewFlagSet("guard list", flag.ExitOnError)
			cfgPath := fs.String("config", "", "Path to YAML configuration file (autodiscovers from ./config.yaml or ~/.faradaiwire/config.yaml)")
			fs.Parse(os.Args[3:])
			code := executeGuardList(*cfgPath, os.Stdout)
			os.Exit(code)
		case "status":
			fs := flag.NewFlagSet("guard status", flag.ExitOnError)
			cfgPath := fs.String("config", "", "Path to YAML configuration file (autodiscovers from ./config.yaml or ~/.faradaiwire/config.yaml)")
			fs.Parse(os.Args[3:])
			code := executeGuardStatus(*cfgPath, os.Stdout)
			os.Exit(code)
		case "install":
			fs := flag.NewFlagSet("guard install", flag.ExitOnError)
			cfgPath := fs.String("config", "", "Path to YAML configuration file (autodiscovers from ./config.yaml or ~/.faradaiwire/config.yaml)")
			args := os.Args[3:]
			var modelID string
			var flagArgs []string
			for i := 0; i < len(args); i++ {
				if strings.HasPrefix(args[i], "-") {
					flagArgs = append(flagArgs, args[i])
					if (args[i] == "--config" || args[i] == "-config") && i+1 < len(args) {
						i++
						flagArgs = append(flagArgs, args[i])
					}
				} else if modelID == "" {
					modelID = args[i]
				} else {
					flagArgs = append(flagArgs, args[i])
				}
			}
			fs.Parse(flagArgs)
			if modelID == "" {
				fmt.Println("Error: install command requires a model ID. Usage: faradaiwire guard install <id> [--config <path>]")
				os.Exit(1)
			}
			code := executeGuardInstall(*cfgPath, modelID, os.Stdout)
			os.Exit(code)
		case "uninstall":
			fs := flag.NewFlagSet("guard uninstall", flag.ExitOnError)
			cfgPath := fs.String("config", "", "Path to YAML configuration file (autodiscovers from ./config.yaml or ~/.faradaiwire/config.yaml)")
			args := os.Args[3:]
			var modelID string
			var flagArgs []string
			for i := 0; i < len(args); i++ {
				if strings.HasPrefix(args[i], "-") {
					flagArgs = append(flagArgs, args[i])
					if (args[i] == "--config" || args[i] == "-config") && i+1 < len(args) {
						i++
						flagArgs = append(flagArgs, args[i])
					}
				} else if modelID == "" {
					modelID = args[i]
				} else {
					flagArgs = append(flagArgs, args[i])
				}
			}
			fs.Parse(flagArgs)
			if modelID == "" {
				fmt.Println("Error: uninstall command requires a model ID. Usage: faradaiwire guard uninstall <id> [--config <path>]")
				os.Exit(1)
			}
			code := executeGuardUninstall(*cfgPath, modelID, os.Stdout)
			os.Exit(code)
		default:
			fmt.Printf("Unknown guard subcommand: %s\n", os.Args[2])
			printGuardUsage()
			os.Exit(1)
		}
	case "version":
		fmt.Printf("FaradAiWire Security Gateway %s\n", version)
	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("FaradAiWire - Zero-Trust AI Agent Security Gateway (%s)\n", version)
	fmt.Println("Usage: faradaiwire run [--config <path>] [--standalone] [--host <host>] [--port <port>] [--admin-port <admin-port>] | doctor [--config <path>] | audit <path|url> [--json] | guard [list|status|install <id>|uninstall <id>] [--config <path>] | version")
}

func executeRun(configPath string, standalone bool, host string, port int, adminPort int) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		slog.Error("Configuration load failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Apply CLI overrides
	if standalone {
		cfg.RuntimeMode = config.RuntimeModeStandalone
	}
	if strings.TrimSpace(host) != "" {
		cfg.ListenHost = strings.TrimSpace(host)
	}
	if port > 0 {
		cfg.ListenPort = port
	}
	if adminPort > 0 {
		cfg.AdminPort = adminPort
	}

	if isInteractiveTerminal() {
		printStartupBanner(cfg, os.Stdout)
	}

	slog.Info("Starting FaradAiWire",
		slog.String("mode", cfg.GetRuntimeMode()),
		slog.String("host", cfg.GetListenHost()),
		slog.Int("port", cfg.GetListenPort()),
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
		os.Exit(1)
	}
	defer func() {
		if err := guard.Release(); err != nil {
			slog.Warn("Failed to release process lock cleanly", slog.String("error", err.Error()))
		}
	}()

	server, err := gateway.NewServer(cfg, provider)
	if err != nil {
		slog.Error("Server initialization failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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
				os.Exit(1)
			}
		}()

		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer sCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server shutdown completed with error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	case err := <-serverErrCh:
		if err != nil {
			slog.Error("Gateway server terminated with error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	slog.Info("FaradAiWire stopped cleanly.")
}

