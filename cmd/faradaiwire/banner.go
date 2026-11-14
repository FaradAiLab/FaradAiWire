package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/slmprobe"
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

// printStartupBanner renders a developer-friendly status summary and contextual SLM hints.
func printStartupBanner(cfg *config.Config, out io.Writer) {
	fmt.Fprintf(out, "\nFaradAiWire v%s (%s Mode)\n", strings.TrimPrefix(version, "v"), cfg.GetRuntimeMode())
	fmt.Fprintf(out, "├── Ingress Proxy   : http://%s:%d (MCP SSE / Stdio)\n", cfg.GetListenHost(), cfg.GetListenPort())
	fmt.Fprintf(out, "├── Admin Console   : http://%s:%d\n", cfg.GetListenHost(), cfg.GetAdminPort())
	fmt.Fprintln(out, "└── Security Engine :")

	// DLP & Secrets
	dlpStatus := statusTag(cfg.Filters.DLP.Enabled)
	fmt.Fprintf(out, "    ├── DLP & Secrets Redaction  : %s\n", dlpStatus)

	// Loop & Rate
	loopOrRate := cfg.Filters.LoopProtection.Enabled || cfg.Filters.RateLimiting.Enabled
	fmt.Fprintf(out, "    ├── Loop & Rate Protection   : %s\n", statusTag(loopOrRate))

	// Prompt Injection Scanner & SLM Discovery Hint
	if !cfg.Filters.InjectionScanner.Enabled {
		fmt.Fprintln(out, "    └── Prompt Injection Scanner : [DISABLED]")
		fmt.Fprintln(out)
		return
	}

	classifierURL := strings.TrimSpace(cfg.Filters.InjectionScanner.ClassifierURL)
	probeCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	probeRes := slmprobe.Probe(probeCtx, classifierURL)

	// Check local DuckDB Model Catalog (GUARD-001 / DEC-01)
	dbPath := cfg.GetTelemetryDBPath()
	models, _ := fetchModelsFromDuckDB(context.Background(), dbPath)
	var activeGuardModel *guard.Model
	for _, m := range models {
		if m.IsActive {
			activeGuardModel = m
			break
		}
	}

	if activeGuardModel != nil {
		fmt.Fprintf(out, "    └── SLM Security Guard       : [ACTIVE - NEURAL] (%s, %.1f%%)\n", activeGuardModel.Name, activeGuardModel.BenchmarkAccuracy*100)
	} else if probeRes.ConfiguredActive {
		modelStr := ""
		if probeRes.ModelName != "" {
			modelStr = fmt.Sprintf(" (%s, %dms)", probeRes.ModelName, probeRes.LatencyMs)
		}
		fmt.Fprintf(out, "    └── Prompt Injection Scanner : [ACTIVE - NEURAL]%s\n", modelStr)
	} else {
		fmt.Fprintln(out, "    └── Prompt Injection Scanner : [STANDBY - REGEX]")
		if probeRes.Detected {
			providerName := "Ollama"
			if probeRes.DetectedProvider == slmprobe.ProviderPromptGuard {
				providerName = "Docker Prompt-Guard"
			}
			fmt.Fprintf(out, "        ↳ 💡 Hint: Detected local %s on %s. Run 'faradai doctor' to activate neural guard.\n", providerName, probeRes.DetectedURL)
		} else {
			fmt.Fprintln(out, "        ↳ 💡 Hint: Running with fast regex guard. Connect local SLM models ('faradai guard list') or Docker ('faradai doctor').")
		}
	}
	fmt.Fprintln(out)
}
