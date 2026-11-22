package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/guardprobe"
)

// isInteractiveTerminal returns true if stdout is an interactive character device and not a CI pipeline.
func isInteractiveTerminal() bool {
	if os.Getenv("CI") == "true" || os.Getenv("FARADAI_WIRE_NO_BANNER") == "true" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// statusTag formats a boolean filter status into a clean bracketed label.
func statusTag(enabled bool) string {
	if enabled {
		return "[ACTIVE]"
	}
	return "[DISABLED]"
}

// printStartupBanner renders a developer-friendly status summary and contextual AI Guard hints.
func printStartupBanner(cfg *config.Config, out io.Writer) {
	adminScheme := "http"
	if cfg != nil && cfg.AdminTLS.Enabled {
		adminScheme = "https"
	}
	transportDesc := "MCP SSE / Stdio"
	if cfg != nil && !cfg.IsStdioAllowed() {
		transportDesc = "MCP HTTP / SSE Only (Containerized)"
	}
	fmt.Fprintf(out, "\nFaradAiWire v%s (%s Mode)\n", strings.TrimPrefix(version, "v"), cfg.GetRuntimeMode())
	fmt.Fprintf(out, "├── Ingress Proxy   : http://%s (%s)\n", net.JoinHostPort(cfg.GetListenHost(), strconv.Itoa(cfg.GetListenPort())), transportDesc)
	fmt.Fprintf(out, "├── Admin Console   : %s://%s\n", adminScheme, net.JoinHostPort(cfg.GetAdminHost(), strconv.Itoa(cfg.GetAdminPort())))
	if adminKeyPrefix := lookupBannerAdminKeyPrefix(cfg); adminKeyPrefix != "" || (cfg != nil && !cfg.IsStdioAllowed()) {
		recoverCmd := "faradaiwire token"
		if cfg != nil && !cfg.IsStdioAllowed() {
			recoverCmd = "docker exec -it faradaiwire faradaiwire token"
		}
		if adminKeyPrefix != "" {
			fmt.Fprintf(out, "├── Bootstrap Key   : %s (recover full key & Magic Link: %s)\n", adminKeyPrefix, recoverCmd)
		} else {
			fmt.Fprintf(out, "├── Bootstrap Key   : recover full key & Magic Link via '%s'\n", recoverCmd)
		}
	}
	fmt.Fprintln(out, "└── Security Engine :")

	// DLP & Secrets
	dlpStatus := statusTag(cfg.Filters.DLP.Enabled)
	fmt.Fprintf(out, "    ├── DLP & Secrets Redaction  : %s\n", dlpStatus)

	// Loop & Rate
	loopOrRate := cfg.Filters.LoopProtection.Enabled || cfg.Filters.RateLimiting.Enabled
	fmt.Fprintf(out, "    ├── Loop & Rate Protection   : %s\n", statusTag(loopOrRate))

	// AI Guard Discovery Hint
	if !cfg.Filters.InjectionScanner.Enabled {
		fmt.Fprintln(out, "    └── AI Guard                 : [DISABLED]")
		fmt.Fprintln(out)
		return
	}

	classifierURL := strings.TrimSpace(cfg.Filters.InjectionScanner.ClassifierURL)
	probeCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	probeRes := guardprobe.ProbeWithDiscovery(
		probeCtx,
		classifierURL,
		cfg.Filters.Guard.Discovery.GetEffectiveDockerURL(),
		cfg.Filters.Guard.Discovery.GetEffectiveOllamaURL(),
	)

	// Check local DuckDB Model Catalog (GUARD-001 / DEC-01)
	dbPath := cfg.GetTelemetryDBPath()
	dbCtx, dbCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer dbCancel()
	models, _ := fetchModelsFromDuckDB(dbCtx, dbPath)
	var activeGuardModel *guard.Model
	for _, m := range models {
		if m.IsActive {
			activeGuardModel = m
			break
		}
	}

	if activeGuardModel != nil {
		fmt.Fprintf(out, "    └── AI Guard                 : [ACTIVE - NEURAL] (%s, %.1f%%)\n", activeGuardModel.Name, activeGuardModel.BenchmarkAccuracy*100)
	} else if probeRes.ConfiguredActive {
		modelStr := ""
		if probeRes.ModelName != "" {
			modelStr = fmt.Sprintf(" (%s, %dms)", probeRes.ModelName, probeRes.LatencyMs)
		}
		fmt.Fprintf(out, "    └── AI Guard                 : [ACTIVE - NEURAL]%s\n", modelStr)
	} else {
		fmt.Fprintln(out, "    └── AI Guard                 : [STANDBY - REGEX]")
		if probeRes.Detected {
			providerName := "Ollama"
			if probeRes.DetectedProvider == guardprobe.ProviderPromptGuard {
				providerName = "Docker FaradAiGuard"
			}
			fmt.Fprintf(out, "        ↳ 💡 Hint: Detected local %s on %s. Run 'faradaiwire doctor' to activate AI Guard.\n", providerName, probeRes.DetectedURL)
		} else {
			fmt.Fprintln(out, "        ↳ 💡 Hint: Running with fast regex guard. Connect local AI Guard models ('faradaiwire guard list') or Docker ('faradaiwire doctor').")
		}
	}
	fmt.Fprintln(out)
}

func lookupBannerAdminKeyPrefix(cfg *config.Config) string {
	if envKey := strings.TrimSpace(os.Getenv("FARADAI_WIRE_API_KEY")); envKey != "" {
		return auth.MaskTokenPrefix(envKey)
	}
	if cfg == nil {
		return ""
	}
	keysPath := cfg.GetAPIKeysPath()
	if _, err := os.Stat(keysPath); err != nil {
		return ""
	}
	ks, err := auth.NewFileKeyStore(keysPath)
	if err != nil {
		return ""
	}
	if adminMeta := findActiveAdminKey(ks); adminMeta != nil && adminMeta.RawKey != "" {
		return auth.MaskTokenPrefix(adminMeta.RawKey)
	}
	return ""
}
