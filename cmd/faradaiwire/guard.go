package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/pathguard"
)

var (
	guardStatusHTTPClient  = &http.Client{Timeout: 500 * time.Millisecond, CheckRedirect: blockRedirects}
	guardDefaultHTTPClient = &http.Client{Timeout: 5 * time.Second, CheckRedirect: blockRedirects}
)

const maxGuardAdminResponseBytes = 4 << 20

func normalizeGuardHost(host string) string {
	return normalizeGatewayHost(host)
}

// ANSI color codes for terminal rendering
const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiCyan      = "\033[36m"
	ansiBoldCyan  = "\033[1;36m"
	ansiBoldWhite = "\033[1;37m"
	ansiGreen     = "\033[32m"
	ansiBoldGreen = "\033[1;32m"
	ansiYellow    = "\033[33m"
	ansiBoldRed   = "\033[1;31m"
)

// fetchModelsFromGateway attempts to retrieve models from a running gateway admin API.
func fetchModelsFromGateway(ctx context.Context, host string, port int, clients ...*http.Client) ([]*guard.Model, error) {
	return fetchModelsFromGatewayWithScheme(ctx, "http", host, port, clients...)
}

func fetchModelsFromGatewayWithScheme(ctx context.Context, scheme string, host string, port int, clients ...*http.Client) ([]*guard.Model, error) {
	if scheme == "" {
		scheme = "http"
	}
	normalizedHost := normalizeGuardHost(host)
	endpoint := fmt.Sprintf("%s://%s/admin/guards/models", scheme, net.JoinHostPort(normalizedHost, strconv.Itoa(port)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create guard models request: %w", err)
	}
	attachAdminBearerAuth(req)

	client := guardStatusHTTPClient
	if len(clients) > 0 && clients[0] != nil {
		client = clients[0]
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch guard models from gateway: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
	}

	var data struct {
		Models []*guard.Model `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxGuardAdminResponseBytes)).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode guard models response: %w", err)
	}
	return data.Models, nil
}

// fetchModelsFromDuckDB retrieves models directly from the local DuckDB database.
func fetchModelsFromDuckDB(ctx context.Context, dbPath string) ([]*guard.Model, error) {
	catalog, err := guard.OpenCatalog(dbPath)
	if err != nil {
		return nil, err
	}
	defer catalog.Close()

	if err := catalog.Migrate(ctx); err != nil {
		return nil, err
	}
	if err := catalog.Seed(ctx); err != nil {
		return nil, err
	}

	return catalog.List(ctx)
}

// RenderModelsTable formats and prints the models catalog as an ANSI-colored table.
func RenderModelsTable(models []*guard.Model, out io.Writer, useColor bool) {
	type rowData struct {
		id       string
		name     string
		family   string
		ram      string
		latency  string
		accuracy string
		status   string
		active   string
	}

	headers := []string{"MODEL", "FAMILY", "RAM REQ", "LATENCY (AVG/P95)", "ACCURACY (FP)", "STATUS", "ACTIVE"}
	rows := make([]rowData, len(models))

	// Initial column widths from headers
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	for i, m := range models {
		displayName := fmt.Sprintf("%s (%s)", m.Name, m.ID)
		ramStr := fmt.Sprintf("%d MB", m.RAMRequiredMB)
		latStr := fmt.Sprintf("%.1fms / %.1fms", m.BenchmarkAvgLatencyMS, m.BenchmarkP95LatencyMS)
		accStr := fmt.Sprintf("%.1f%% (%.1f%%)", m.BenchmarkAccuracy*100, m.BenchmarkFPRate*100)
		statusStr := string(m.InstallStatus)
		activeStr := "NO"
		if m.IsActive {
			activeStr = "YES"
		}

		r := rowData{
			id:       m.ID,
			name:     displayName,
			family:   m.Family,
			ram:      ramStr,
			latency:  latStr,
			accuracy: accStr,
			status:   statusStr,
			active:   activeStr,
		}
		rows[i] = r

		if len(r.name) > widths[0] {
			widths[0] = len(r.name)
		}
		if len(r.family) > widths[1] {
			widths[1] = len(r.family)
		}
		if len(r.ram) > widths[2] {
			widths[2] = len(r.ram)
		}
		if len(r.latency) > widths[3] {
			widths[3] = len(r.latency)
		}
		if len(r.accuracy) > widths[4] {
			widths[4] = len(r.accuracy)
		}
		if len(r.status) > widths[5] {
			widths[5] = len(r.status)
		}
		if len(r.active) > widths[6] {
			widths[6] = len(r.active)
		}
	}

	borderH := func(left, mid, cross, right string) string {
		var parts []string
		for _, w := range widths {
			parts = append(parts, strings.Repeat(mid, w+2))
		}
		return left + strings.Join(parts, cross) + right
	}

	borderColor := ""
	headerColor := ""
	reset := ""
	if useColor {
		borderColor = ansiCyan
		headerColor = ansiBoldWhite
		reset = ansiReset
	}

	// Top border
	fmt.Fprintf(out, "%s%s%s\n", borderColor, borderH("┌", "─", "┬", "┐"), reset)

	// Header row
	var headerCells []string
	for i, h := range headers {
		cell := fmt.Sprintf(" %-*s ", widths[i], h)
		if useColor {
			cell = fmt.Sprintf(" %s%-*s%s ", headerColor, widths[i], h, reset)
		}
		headerCells = append(headerCells, cell)
	}
	fmt.Fprintf(out, "%s│%s%s%s│%s\n", borderColor, reset, strings.Join(headerCells, borderColor+"│"+reset), borderColor, reset)

	// Header separator
	fmt.Fprintf(out, "%s%s%s\n", borderColor, borderH("├", "─", "┼", "┤"), reset)

	// Data rows
	for _, r := range rows {
		coloredStatus := r.status
		coloredActive := r.active
		coloredName := r.name

		if useColor {
			coloredName = fmt.Sprintf("%s%s%s", ansiBoldCyan, r.name, reset)
			switch r.status {
			case string(guard.InstallStatusInstalled):
				coloredStatus = fmt.Sprintf("%s%s%s", ansiBoldGreen, r.status, reset)
			case string(guard.InstallStatusInstalling):
				coloredStatus = fmt.Sprintf("%s%s%s", ansiYellow, r.status, reset)
			case string(guard.InstallStatusFailed):
				coloredStatus = fmt.Sprintf("%s%s%s", ansiBoldRed, r.status, reset)
			default:
				coloredStatus = fmt.Sprintf("%s%s%s", ansiDim, r.status, reset)
			}

			if r.active == "YES" {
				coloredActive = fmt.Sprintf("%s%s%s", ansiBoldGreen, r.active, reset)
			} else {
				coloredActive = fmt.Sprintf("%s%s%s", ansiDim, r.active, reset)
			}
		}

		c0 := fmt.Sprintf(" %s%s ", coloredName, strings.Repeat(" ", widths[0]-len(r.name)))
		c1 := fmt.Sprintf(" %-*s ", widths[1], r.family)
		c2 := fmt.Sprintf(" %-*s ", widths[2], r.ram)
		c3 := fmt.Sprintf(" %-*s ", widths[3], r.latency)
		c4 := fmt.Sprintf(" %-*s ", widths[4], r.accuracy)
		c5 := fmt.Sprintf(" %s%s ", coloredStatus, strings.Repeat(" ", widths[5]-len(r.status)))
		c6 := fmt.Sprintf(" %s%s ", coloredActive, strings.Repeat(" ", widths[6]-len(r.active)))

		cells := []string{c0, c1, c2, c3, c4, c5, c6}
		rowStr := fmt.Sprintf("%s│%s%s%s│%s", borderColor, reset, strings.Join(cells, borderColor+"│"+reset), borderColor, reset)
		fmt.Fprintln(out, rowStr)
	}

	// Bottom border
	fmt.Fprintf(out, "%s%s%s\n", borderColor, borderH("└", "─", "┴", "┘"), reset)
}

// executeGuardList implements the 'faradai guard list' command.
func executeGuardList(configPath string, out io.Writer) int {
	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		cfg = &config.Config{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var models []*guard.Model

	// 1. Try querying running gateway admin REST endpoint first
	host := resolveAdminEndpointHost(cfg)
	adminPort := cfg.GetAdminPort()
	if target := net.JoinHostPort(host, strconv.Itoa(adminPort)); target != "" {
		m, err := fetchModelsFromGatewayWithScheme(ctx, adminScheme(cfg), host, adminPort)
		if err == nil && len(m) > 0 {
			models = m
		}
	}

	// 2. If gateway is offline, read from embedded DuckDB directly
	if len(models) == 0 {
		dbPath := cfg.GetTelemetryDBPath()
		m, err := fetchModelsFromDuckDB(ctx, dbPath)
		if err != nil {
			fmt.Fprintf(out, "Error: unable to query DuckDB guard catalog (%v)\n", err)
			return 1
		}
		models = m
	}

	useColor := os.Getenv("NO_COLOR") == ""
	RenderModelsTable(models, out, useColor)
	return 0
}

// fetchGuardStatusFromGateway queries the runtime status from the admin REST endpoint.
func fetchGuardStatusFromGateway(ctx context.Context, host string, port int, clients ...*http.Client) (*guard.ProcessStatus, error) {
	return fetchGuardStatusFromGatewayWithScheme(ctx, "http", host, port, clients...)
}

func fetchGuardStatusFromGatewayWithScheme(ctx context.Context, scheme string, host string, port int, clients ...*http.Client) (*guard.ProcessStatus, error) {
	if scheme == "" {
		scheme = "http"
	}
	normalizedHost := normalizeGuardHost(host)
	endpoint := fmt.Sprintf("%s://%s/admin/guards/status", scheme, net.JoinHostPort(normalizedHost, strconv.Itoa(port)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create guard status request: %w", err)
	}
	attachAdminBearerAuth(req)

	client := guardStatusHTTPClient
	if len(clients) > 0 && clients[0] != nil {
		client = clients[0]
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch guard status from gateway: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
	}

	var status guard.ProcessStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxGuardAdminResponseBytes)).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode guard status response: %w", err)
	}
	return &status, nil
}

// RenderGuardStatus formats and prints the active process status to out.
func RenderGuardStatus(status *guard.ProcessStatus, out io.Writer, useColor bool) {
	reset := ansiReset
	bold := ansiBold
	dim := ansiDim
	cyan := ansiBoldCyan
	green := ansiBoldGreen
	yellow := ansiYellow
	red := ansiBoldRed

	if !useColor {
		reset = ""
		bold = ""
		dim = ""
		cyan = ""
		green = ""
		yellow = ""
		red = ""
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s╭────────────────────────────────────────────────────────────╮%s\n", cyan, reset)
	fmt.Fprintf(out, "%s│%s         %sFarad Ai SLM Security Guard Process Status%s         %s│%s\n", cyan, reset, bold, reset, cyan, reset)
	fmt.Fprintf(out, "%s╰────────────────────────────────────────────────────────────╯%s\n", cyan, reset)
	fmt.Fprintln(out)

	if status == nil || !status.Running {
		healthStr := "STOPPED"
		if status != nil && status.HealthStatus != "" {
			healthStr = status.HealthStatus
		}
		fmt.Fprintf(out, "  %sShield Mode%s    : %sL1 Static Rules Only (Fast Regex / Heuristics)%s\n", bold, reset, dim, reset)
		fmt.Fprintf(out, "  %sHealth Status%s  : %s%s%s\n", bold, reset, yellow, healthStr, reset)
		fmt.Fprintf(out, "  %sSubprocess%s     : %sInactive (No L2 SLM guard running)%s\n", bold, reset, dim, reset)
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  %s💡 Hint:%s Run %sfaradai guard list%s to inspect models or activate via admin console.\n", dim, reset, bold, reset)
		fmt.Fprintln(out)
		return
	}

	statusColor := green
	if status.HealthStatus == "DEGRADED" {
		statusColor = yellow
	} else if status.HealthStatus == "FAILED" {
		statusColor = red
	}

	modelID := status.ModelID
	if modelID == "" {
		modelID = "unknown"
	}

	uptimeStr := "n/a"
	if status.StartedAt != nil {
		uptime := time.Since(*status.StartedAt).Round(time.Second)
		uptimeStr = uptime.String()
	}

	fmt.Fprintf(out, "  %sShield Mode%s    : %sFail-Fast Cascade (L1 Heuristics + L2 Neural SLM)%s\n", bold, reset, green, reset)
	fmt.Fprintf(out, "  %sHealth Status%s  : %s%s%s\n", bold, reset, statusColor, status.HealthStatus, reset)
	fmt.Fprintf(out, "  %sActive Model%s   : %s%s%s\n", bold, reset, cyan, modelID, reset)
	fmt.Fprintf(out, "  %sPID%s            : %s%d%s\n", bold, reset, bold, status.PID, reset)
	fmt.Fprintf(out, "  %sMemory (RSS)%s   : %s%.1f MB%s\n", bold, reset, bold, status.MemoryRSSMB, reset)
	fmt.Fprintf(out, "  %sUptime%s         : %s%s%s\n", bold, reset, dim, uptimeStr, reset)
	fmt.Fprintln(out)
}

// executeGuardStatus implements the 'faradai guard status' command.
func executeGuardStatus(configPath string, out io.Writer, client ...*http.Client) int {
	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		cfg = &config.Config{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	host := resolveAdminEndpointHost(cfg)
	adminPort := cfg.GetAdminPort()

	useColor := os.Getenv("NO_COLOR") == ""

	status, err := fetchGuardStatusFromGatewayWithScheme(ctx, adminScheme(cfg), host, adminPort, client...)
	if err != nil {
		fmt.Fprintf(out, "\n%sFaradAiWire is offline or admin API unreachable at %s:%d.%s\n", ansiDim, host, adminPort, ansiReset)
		// Render offline/stopped state
		RenderGuardStatus(&guard.ProcessStatus{
			Running:      false,
			HealthStatus: "STOPPED",
		}, out, useColor)
		return 0
	}

	RenderGuardStatus(status, out, useColor)
	return 0
}

// executeGuardInstall implements the 'faradai guard install <id>' command.
func executeGuardInstall(configPath string, modelID string, out io.Writer, client ...*http.Client) int {
	if strings.TrimSpace(modelID) == "" {
		fmt.Fprintln(out, "Error: model ID is required")
		return 1
	}

	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		fmt.Fprintf(out, "Error: invalid model ID '%s': %v\n", modelID, err)
		return 1
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		cfg = &config.Config{}
	}

	host := resolveAdminEndpointHost(cfg)
	adminPort := cfg.GetAdminPort()
	scheme := adminScheme(cfg)
	hostPort := net.JoinHostPort(host, strconv.Itoa(adminPort))
	escapedModelID := url.PathEscape(modelID)
	installURL := fmt.Sprintf("%s://%s/admin/guards/models/%s/install", scheme, hostPort, escapedModelID)

	httpClient := guardDefaultHTTPClient
	if len(client) > 0 && client[0] != nil {
		httpClient = client[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, installURL, nil)
	var resp *http.Response
	if err == nil {
		attachAdminBearerAuth(req)
		resp, err = httpClient.Do(req)
	}

	// If gateway responded
	if err != nil || resp == nil {
		cancel()
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(out, "Error: model '%s' not found in catalog\n", modelID)
			return 1
		}
		if resp.StatusCode == http.StatusConflict {
			fmt.Fprintf(out, "Installation already in progress for model '%s'\n", modelID)
			return 1
		}
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			fmt.Fprintf(out, "Error: gateway returned HTTP %d\n", resp.StatusCode)
			return 1
		}

		fmt.Fprintf(out, "Initiating installation for model '%s' via FaradAiWire...\n", modelID)

		// Poll progress
		progressURL := fmt.Sprintf("%s://%s/admin/guards/models/%s/progress", scheme, hostPort, escapedModelID)
		lastStep := ""
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			pCtx, pCancel := context.WithTimeout(context.Background(), 2*time.Second)
			pReq, pErr := http.NewRequestWithContext(pCtx, http.MethodGet, progressURL, nil)
			if pErr != nil {
				pCancel()
				continue
			}
			attachAdminBearerAuth(pReq)
			pResp, pErr := httpClient.Do(pReq)
			if pErr != nil {
				pCancel()
				continue
			}

			var prog guard.InstallProgress
			pErr = json.NewDecoder(io.LimitReader(pResp.Body, maxGuardAdminResponseBytes)).Decode(&prog)
			pResp.Body.Close()
			pCancel()
			if pErr != nil {
				continue
			}

			if string(prog.Step) != lastStep {
				lastStep = string(prog.Step)
				if prog.Step != guard.StepCompleted && prog.Step != guard.StepFailed {
					fmt.Fprintf(out, "  [%s] %s (%.0f%%)\n", prog.Step, prog.Message, prog.Progress*100)
				}
			}

			if prog.Status == guard.InstallStatusInstalled || prog.Step == guard.StepCompleted {
				fmt.Fprintf(out, "Successfully installed model '%s'. Status is now INSTALLED.\n", modelID)
				return 0
			}
			if prog.Status == guard.InstallStatusFailed || prog.Step == guard.StepFailed {
				fmt.Fprintf(out, "Installation failed: %s\n", prog.Error)
				return 1
			}
		}

		fmt.Fprintf(out, "Installation timed out waiting for progress completion\n")
		return 1
	}

	// Gateway unreachable: execute standalone direct installation via embedded DuckDB
	fmt.Fprintf(out, "FaradAiWire offline, executing standalone direct installation for '%s'...\n", modelID)
	dbPath := cfg.GetTelemetryDBPath()
	catalog, catErr := guard.OpenCatalog(dbPath)
	if catErr != nil {
		fmt.Fprintf(out, "Error: unable to open DuckDB catalog (%v)\n", catErr)
		return 1
	}
	defer catalog.Close()

	directCtx, directCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer directCancel()

	_ = catalog.Migrate(directCtx)
	_ = catalog.Seed(directCtx)

	installer := guard.NewInstaller(guard.InstallerConfig{
		BaseDir: os.Getenv("FARADAI_WIRE_GUARDS_DIR"),
		Catalog: catalog,
	})
	if installErr := installer.Install(directCtx, modelID); installErr != nil {
		fmt.Fprintf(out, "Installation failed: %v\n", installErr)
		return 1
	}

	fmt.Fprintf(out, "Successfully installed model '%s'. Status is now INSTALLED.\n", modelID)
	return 0
}

// executeGuardUninstall implements the 'faradai guard uninstall <id>' command.
func executeGuardUninstall(configPath string, modelID string, out io.Writer, client ...*http.Client) int {
	if strings.TrimSpace(modelID) == "" {
		fmt.Fprintln(out, "Error: model ID is required")
		return 1
	}
	if err := pathguard.ValidateSafeIdentifier(modelID); err != nil {
		fmt.Fprintf(out, "Error: invalid model ID '%s': %v\n", modelID, err)
		return 1
	}

	provider := config.NewYAMLConfigProvider(configPath)
	cfg, err := provider.Load()
	if err != nil {
		cfg = &config.Config{}
	}

	host := resolveAdminEndpointHost(cfg)
	adminPort := cfg.GetAdminPort()
	scheme := adminScheme(cfg)
	deleteURL := fmt.Sprintf("%s://%s/admin/guards/models/%s", scheme, net.JoinHostPort(host, strconv.Itoa(adminPort)), url.PathEscape(modelID))

	httpClient := guardDefaultHTTPClient
	if len(client) > 0 && client[0] != nil {
		httpClient = client[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteURL, nil)
	var resp *http.Response
	if err == nil {
		attachAdminBearerAuth(req)
		resp, err = httpClient.Do(req)
	}

	// If gateway responded
	if err == nil && resp != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(out, "Error: model '%s' not found in catalog\n", modelID)
			return 1
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(out, "Error: gateway returned HTTP %d\n", resp.StatusCode)
			return 1
		}
		fmt.Fprintf(out, "Successfully uninstalled model '%s'. Purged model directory and reverted state to NOT_INSTALLED.\n", modelID)
		return 0
	}

	// Gateway unreachable: execute standalone direct uninstallation via embedded DuckDB
	fmt.Fprintf(out, "FaradAiWire offline, executing standalone direct uninstallation for '%s'...\n", modelID)
	dbPath := cfg.GetTelemetryDBPath()
	catalog, catErr := guard.OpenCatalog(dbPath)
	if catErr != nil {
		fmt.Fprintf(out, "Error: unable to open DuckDB catalog (%v)\n", catErr)
		return 1
	}
	defer catalog.Close()

	directCtx, directCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer directCancel()

	_ = catalog.Migrate(directCtx)
	_ = catalog.Seed(directCtx)

	installer := guard.NewInstaller(guard.InstallerConfig{
		BaseDir: os.Getenv("FARADAI_WIRE_GUARDS_DIR"),
		Catalog: catalog,
	})
	if unErr := installer.Uninstall(directCtx, modelID); unErr != nil {
		fmt.Fprintf(out, "Uninstall failed: %v\n", unErr)
		return 1
	}

	fmt.Fprintf(out, "Successfully uninstalled model '%s'. Purged model directory and reverted state to NOT_INSTALLED.\n", modelID)
	return 0
}

func printGuardUsage() {
	printGuardUsageTo(os.Stdout)
}
