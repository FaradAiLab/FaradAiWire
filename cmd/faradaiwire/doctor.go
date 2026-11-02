package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/slmprobe"
)

// checkPortStatus checks if a local TCP port is already bound or available.
func checkPortStatus(host string, port int) (inUse bool, err error) {
	if host == "" {
		host = "127.0.0.1"
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	conn, dialErr := net.DialTimeout("tcp", target, 60*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		return true, nil // Port is currently bound by a process
	}
	return false, nil // Port is free
}

// checkStorageWritable verifies write permissions in the target directory.
func checkStorageWritable(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	probeFile := filepath.Join(dir, fmt.Sprintf(".faradai_probe_%d", time.Now().UnixNano()))
	if err := os.WriteFile(probeFile, []byte("ok"), 0600); err != nil {
		return err
	}
	_ = os.Remove(probeFile)
	return nil
}

// executeDoctor runs all system and SLM diagnostic checks, writing human-readable output to out.
func executeDoctor(configPath string, out io.Writer) int {
	fmt.Fprintln(out, "FaradAiWire Diagnostic Report (Doctor)")
	fmt.Fprintln(out, "==========================================")

	allOK := true

	// 1. Config Discovery & Validation
	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		fmt.Fprintf(out, "[✗] Configuration: Failed to load config (%v)\n", err)
		return 1
	}
	fmt.Fprintf(out, "[✓] Configuration: %s (mode: %s)\n", cfg.ConfigPath, cfg.GetRuntimeMode())

	// 2. Port Availability / Status
	ingressPort := cfg.GetListenPort()
	adminPort := cfg.GetAdminPort()

	inUseIngress, errIngress := checkPortStatus(cfg.GetListenHost(), ingressPort)
	if errIngress != nil {
		fmt.Fprintf(out, "[!] Ingress Port :%d: Check skipped (%v)\n", ingressPort, errIngress)
	} else if inUseIngress {
		fmt.Fprintf(out, "[✓] Ingress Port :%d: In use / active\n", ingressPort)
	} else {
		fmt.Fprintf(out, "[✓] Ingress Port :%d: Available\n", ingressPort)
	}

	inUseAdmin, errAdmin := checkPortStatus(cfg.GetListenHost(), adminPort)
	if errAdmin != nil {
		fmt.Fprintf(out, "[!] Admin Port   :%d: Check skipped (%v)\n", adminPort, errAdmin)
	} else if inUseAdmin {
		fmt.Fprintf(out, "[✓] Admin Port   :%d: In use / active\n", adminPort)
	} else {
		fmt.Fprintf(out, "[✓] Admin Port   :%d: Available\n", adminPort)
	}

	// 3. Storage & Directory Permissions
	storageDir := filepath.Dir(cfg.ConfigPath)
	if storageDir == "" || storageDir == "." {
		storageDir = os.Getenv("FARADAI_WIRE_HOME")
		if storageDir == "" {
			storageDir = "."
		}
	}
	if err := checkStorageWritable(storageDir); err != nil {
		fmt.Fprintf(out, "[✗] Storage      : Directory not writable (%s: %v)\n", storageDir, err)
		allOK = false
	} else {
		fmt.Fprintf(out, "[✓] Storage      : Writable at %s\n", storageDir)
	}

	// 4. SLM Classifier Discovery & Diagnosis
	classifierURL := ""
	if cfg.Filters.InjectionScanner.Enabled {
		classifierURL = cfg.Filters.InjectionScanner.ClassifierURL
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	probeRes := slmprobe.Probe(probeCtx, classifierURL)

	// Check local DuckDB Model Catalog (GUARD-001 / DEC-01)
	dbPath := ""
	if cfg != nil {
		dbPath = cfg.GetTelemetryDBPath()
	} else {
		dbPath = filepath.Join(storageDir, "wire.duckdb")
	}
	models, _ := fetchModelsFromDuckDB(context.Background(), dbPath)
	var activeGuardModel *guard.Model
	var installedModels []*guard.Model
	for _, m := range models {
		if m.IsActive {
			activeGuardModel = m
		}
		if m.InstallStatus == guard.InstallStatusInstalled {
			installedModels = append(installedModels, m)
		}
	}

	fmt.Fprintln(out, "------------------------------------------")
	if activeGuardModel != nil {
		fmt.Fprintf(out, "[✓] Neural SLM   : ACTIVE (Local Guard: %s via Stdio MCP)\n", activeGuardModel.Name)
		fmt.Fprintf(out, "    ↳ Model       : %s (%s, %.1f%% Benchmark Accuracy)\n", activeGuardModel.ID, activeGuardModel.Family, activeGuardModel.BenchmarkAccuracy*100)
		fmt.Fprintf(out, "    ↳ Best For    : %s\n", activeGuardModel.RecommendedFor)
		if probeRes.ConfiguredActive {
			fmt.Fprintf(out, "    ↳ External    : %s (%dms)\n", probeRes.ConfiguredURL, probeRes.LatencyMs)
		}
	} else if probeRes.ConfiguredActive {
		fmt.Fprintf(out, "[✓] Neural SLM   : ACTIVE (connected to %s)\n", probeRes.ConfiguredURL)
		if probeRes.ModelName != "" {
			fmt.Fprintf(out, "    ↳ Model       : %s\n", probeRes.ModelName)
		}
		fmt.Fprintf(out, "    ↳ Latency     : %dms round-trip\n", probeRes.LatencyMs)
	} else if len(installedModels) > 0 {
		fmt.Fprintf(out, "[!] Neural SLM   : Standby (%d local model(s) installed, but none active)\n", len(installedModels))
		fmt.Fprintf(out, "    ↳ Installed   : %s\n", installedModels[0].Name)
		fmt.Fprintf(out, "    ↳ To activate : Run 'faradai guard activate %s' or activate in Web Console\n", installedModels[0].ID)
	} else if probeRes.Detected {
		fmt.Fprintf(out, "[!] Neural SLM   : Standby (Detected local %s at %s, but not active in config)\n", probeRes.DetectedProvider, probeRes.DetectedURL)
		if probeRes.ModelName != "" {
			fmt.Fprintf(out, "    ↳ Model       : %s\n", probeRes.ModelName)
		}
		fmt.Fprintln(out, "    ↳ To activate : Add to your config.yaml under filters.guard:")
		if probeRes.DetectedProvider == slmprobe.ProviderPromptGuard {
			fmt.Fprintf(out, "                    custom_url: \"%s\"\n", probeRes.DetectedURL)
		} else {
			fmt.Fprintf(out, "                    custom_url: \"%s\"\n", probeRes.DetectedURL)
		}
	} else {
		fmt.Fprintln(out, "[-] Neural SLM   : Standby (Static Heuristics & Regex active)")
		fmt.Fprintln(out, "    ↳ Tip         : Connect or activate an SLM for zero-day prompt injection defense:")
		fmt.Fprintln(out, "      • Option A (Ollama - Recommended):")
		fmt.Fprintln(out, "        $ ollama run faradailab/guard-qwen3")
		fmt.Fprintln(out, "        Auto-detected on :11434 with zero configuration.")
		fmt.Fprintln(out, "      • Option B (Docker Container):")
		fmt.Fprintln(out, "        $ docker run -d -p 8000:8000 ghcr.io/faradailab/farad-ai-guard:qwen3")
		fmt.Fprintln(out, "        Auto-detected on :8000 with zero configuration.")
		fmt.Fprintln(out, "      • Option C (Admin Web Console):")
		fmt.Fprintln(out, "        Visit http://localhost:8095 -> Settings -> SLM Probe")
	}
	fmt.Fprintln(out, "==========================================")

	if !allOK {
		return 1
	}
	return 0
}
