package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/guardprobe"
	"github.com/FaradAiLab/FaradAiWire/internal/settings"
	"github.com/FaradAiLab/FaradAiWire/web"
)

func (a *AdminServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if rawToken := strings.TrimSpace(r.URL.Query().Get("token")); rawToken != "" {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if !a.authenticateAndSetSessionCookie(w, r, rawToken, "magic_link", false) {
			return
		}
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}
	web.Handler().ServeHTTP(w, r)
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.Config()
	mgr := a.guardManager
	catalog := a.guardCatalog

	var (
		listenPort         = config.DefaultListenPort
		listenHost         = "127.0.0.1"
		runtimeMode        string
		transportMode      string
		isManaged          bool
		injClassifierURL   string
		autoSyncMCP        bool
		autoUpdatePolicies bool
		pollIntervalSec    int
	)

	if cfg != nil {
		injClassifierURL = cfg.Filters.InjectionScanner.ClassifierURL
		autoSyncMCP = cfg.AutoSyncMCP
		autoUpdatePolicies = cfg.AutoUpdatePolicies
		pollIntervalSec = cfg.PollIntervalSeconds
		runtimeMode = cfg.GetRuntimeMode()
		transportMode = cfg.Mode
		isManaged = cfg.IsManaged()
		if cfg.GetListenPort() > 0 {
			listenPort = cfg.GetListenPort()
		}
		if cfg.GetListenHost() != "" {
			listenHost = cfg.GetListenHost()
		}
	}

	filterSummary := settings.BuildFilterStatusSummary(cfg)
	activeFilters := filterSummary.ActiveFilters
	injScannerEnabled := filterSummary.ConfigStates["injection_scanner"]

	gatewayID := strings.TrimSpace(os.Getenv("GATEWAY_ID"))

	classifierURL := ""
	guardTier := "disabled"
	guardStatus := "standby"
	guardModel := "L1 Static Rules (Fallback)"
	guardEndpoint := "In-Memory Precompiled Regex"
	var guardLatencyMS float64 = 0.2

	// Priority 1: Check active running AI Guard (Qwen3Guard, Mica, Granite Guardian)
	if mgr != nil && mgr.IsRunning() {
		procStatus := mgr.Status()
		guardTier = "neural_active"
		guardStatus = "active"
		guardModel = procStatus.ModelID
		guardEndpoint = fmt.Sprintf("stdio:%s (PID %d)", procStatus.ModelID, procStatus.PID)
		guardLatencyMS = 0
		if catalog != nil && r != nil {
			if m, err := catalog.Get(r.Context(), procStatus.ModelID); err == nil && m != nil {
				guardModel = m.Name
				if m.BenchmarkAvgLatencyMS > 0 {
					guardLatencyMS = m.BenchmarkAvgLatencyMS
				}
			}
		}
		if lr, ok := mgr.(guard.LatencyReporter); ok && lr != nil {
			if measured := lr.AverageLatencyMS(); measured > 0 {
				guardLatencyMS = math.Round(measured*100) / 100
			}
		}
		classifierURL = guardEndpoint
	} else if injScannerEnabled {
		// Priority 2: Check external HTTP classifier URL
		classifierURL = strings.TrimSpace(injClassifierURL)
		if classifierURL != "" {
			guardTier = "neural_active"
			guardStatus = "active"
			guardModel = "External HTTP Classifier"
			guardEndpoint = redactURLCredentials(classifierURL)
			guardLatencyMS = 0
			if lr, ok := mgr.(guard.LatencyReporter); ok && lr != nil {
				if measured := lr.AverageLatencyMS(); measured > 0 {
					guardLatencyMS = math.Round(measured*100) / 100
				}
			}
		} else {
			guardTier = "regex_standby"
			guardStatus = "standby"
		}
	}

	ingressURL := fmt.Sprintf("http://%s:%d", listenHost, listenPort)

	configResp := make(map[string]interface{}, len(filterSummary.ConfigStates)+3)
	for name, enabled := range filterSummary.ConfigStates {
		configResp[name] = enabled
	}
	configResp["auto_sync_mcp"] = autoSyncMCP
	configResp["auto_update_policies"] = autoUpdatePolicies
	configResp["poll_interval_seconds"] = pollIntervalSec

	resp := map[string]interface{}{
		"version":             config.GetVersion(),
		"active_filters":      activeFilters,
		"gateway_id":          gatewayID,
		"status":              "Ready",
		"ingress_port":        listenPort,
		"ingress_host":        listenHost,
		"ingress_url":         ingressURL,
		"mode":                runtimeMode,
		"runtime_mode":        runtimeMode,
		"transport_mode":      transportMode,
		"allow_stdio":         a.isStdioAllowed(),
		"admin_auth_required": a.isAdminAuthRequired(),
		"has_local_overrides": false,
		"is_managed":          isManaged,
		"organization":        "Corporate Organization",
		"locked_editing":      isManaged,
		"guard_tier":          guardTier,
		"guard_model":         guardModel,
		"guard_endpoint":      guardEndpoint,
		"guard_latency_ms":    guardLatencyMS,
		"guard_status": map[string]interface{}{
			"tier":           guardTier,
			"classifier_url": redactURLCredentials(classifierURL),
			"model":          guardModel,
			"active":         guardStatus == "active",
		},
		"config": configResp,
	}

	writeJSON(w, http.StatusOK, resp)
}

// validateGuardURL enforces pragmatic standalone security guardrails:
// - Length <= 2048 chars
// - Valid HTTP or HTTPS scheme
// - Non-empty host
// - Strict rejection of link-local cloud metadata (169.254.169.254 / fe80::/10)
// - Permits loopback (127.0.0.1, ::1) and local LAN RFC1918 IPs for local developer tooling
func validateGuardURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	if len(rawURL) > 2048 {
		return errors.New("URL exceeds maximum length of 2048 characters")
	}
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return errors.New("invalid URL format: " + err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("unsupported scheme: only http and https are allowed")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("missing host in URL")
	}

	// Unconditional guard: Block link-local and cloud metadata (AWS/GCP/Azure/OpenStack IMDS v4 & v6)
	if host == "169.254.169.254" || strings.HasPrefix(host, "169.254.") {
		return errors.New("access to link-local cloud metadata is strictly prohibited")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			ip = ipv4
		}
		if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254")) {
			return errors.New("access to cloud metadata service is strictly prohibited")
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return errors.New("access to link-local metadata is strictly prohibited")
		}
	}

	return nil
}

// redactURLCredentials masks sensitive userinfo passwords in URLs for diagnostic output (ADR 0027).
func redactURLCredentials(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return rawURL
	}
	return u.Redacted()
}

func (a *AdminServer) handleGuardProbe(w http.ResponseWriter, r *http.Request) {
	classifierURL := ""
	if cfg := a.Config(); cfg != nil {
		classifierURL = cfg.Filters.InjectionScanner.ClassifierURL
	}

	// If query param or body overrides target URL (e.g. Test Connection)
	if target := strings.TrimSpace(r.URL.Query().Get("url")); target != "" {
		classifierURL = target
	} else if r.Method == http.MethodPost && r.Body != nil {
		var payload struct {
			URL string `json:"url"`
		}
		if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &payload); err != nil {
			if !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON payload: "+err.Error())
				return
			}
		} else if payload.URL != "" {
			classifierURL = strings.TrimSpace(payload.URL)
		}
	}

	if classifierURL != "" {
		if err := validateGuardURL(classifierURL); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_TARGET", "Invalid probe target: "+err.Error())
			return
		}
	} else {
		mgr := a.getGuardManager()
		if mgr != nil && mgr.IsRunning() {
			status := mgr.Status()
			modelName := status.ModelID
			cat := a.getGuardCatalog()
			if cat != nil {
				if m, mErr := cat.Get(r.Context(), status.ModelID); mErr == nil && m != nil {
					modelName = m.Name
				}
			}
			configuredURL := fmt.Sprintf("http:%s", status.ModelID)
			if status.PID > 0 {
				configuredURL = fmt.Sprintf("stdio:%s (PID %d)", status.ModelID, status.PID)
			}
			probeRes := guardprobe.ProbeResult{
				ConfiguredActive: true,
				ConfiguredURL:    configuredURL,
				Detected:         true,
				DetectedProvider: guardprobe.ProviderCustom,
				DetectedURL:      fmt.Sprintf("http:%s", status.ModelID),
				LatencyMs:        5,
				ModelName:        modelName,
			}
			writeJSON(w, http.StatusOK, probeRes)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 400*time.Millisecond)
	defer cancel()

	var dockerURL, ollamaURL string
	if cfg := a.Config(); cfg != nil {
		dockerURL = cfg.Filters.Guard.Discovery.GetEffectiveDockerURL()
		ollamaURL = cfg.Filters.Guard.Discovery.GetEffectiveOllamaURL()
	}
	probeRes := guardprobe.ProbeWithDiscovery(ctx, classifierURL, dockerURL, ollamaURL)
	probeRes.ConfiguredURL = redactURLCredentials(probeRes.ConfiguredURL)

	writeJSON(w, http.StatusOK, probeRes)
}

func (a *AdminServer) handleGuardConfigure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClassifierURL string `json:"classifier_url"`
		Enabled       *bool  `json:"enabled"`
		Mode          string `json:"mode"`
		OllamaURL     string `json:"ollama_url"`
		DockerURL     string `json:"docker_url"`
		CustomURL     string `json:"custom_url"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	targetURL := strings.TrimSpace(req.ClassifierURL)
	if targetURL == "" && req.CustomURL != "" {
		targetURL = strings.TrimSpace(req.CustomURL)
	}

	for _, field := range []struct {
		label string
		raw   string
	}{
		{"classifier URL", targetURL},
		{"ollama URL", strings.TrimSpace(req.OllamaURL)},
		{"docker URL", strings.TrimSpace(req.DockerURL)},
		{"custom URL", strings.TrimSpace(req.CustomURL)},
	} {
		if field.raw != "" {
			if err := validateGuardURL(field.raw); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_TARGET", "Invalid "+field.label+": "+err.Error())
				return
			}
		}
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	applyGuardMutation := func(cfg *config.Config) {
		if req.Mode != "" {
			cfg.Filters.Guard.Discovery.Mode = req.Mode
		}
		if req.OllamaURL != "" {
			cfg.Filters.Guard.Discovery.OllamaURL = strings.TrimSpace(req.OllamaURL)
		}
		if req.DockerURL != "" {
			cfg.Filters.Guard.Discovery.DockerURL = strings.TrimSpace(req.DockerURL)
		}
		if req.CustomURL != "" {
			cfg.Filters.Guard.Discovery.CustomURL = strings.TrimSpace(req.CustomURL)
		}
		if targetURL != "" {
			cfg.Filters.InjectionScanner.ClassifierURL = targetURL
		}
		if req.Enabled != nil {
			cfg.Filters.InjectionScanner.Enabled = *req.Enabled
			cfg.Filters.Guard.Enabled = *req.Enabled
		} else if targetURL != "" {
			cfg.Filters.InjectionScanner.Enabled = true
			cfg.Filters.Guard.Enabled = true
		}
	}

	origCfg := a.Config()
	cfgProvider := a.cfgProvider
	reloadCfgFn := a.reloadConfigFunc
	reloadFn := a.reloadFunc
	var nextCfg *config.Config
	if origCfg != nil {
		nextCfg = origCfg.Clone()
	}

	if nextCfg != nil {
		applyGuardMutation(nextCfg)
	}

	if reloadCfgFn == nil && reloadFn != nil && nextCfg != nil && cfgProvider != nil {
		if err := cfgProvider.Save(nextCfg); err != nil {
			writeError(w, http.StatusInternalServerError, "SAVE_FAILED", "Failed to save configuration: "+err.Error())
			return
		}
		if err := a.applyConfigReload(nextCfg); err != nil {
			_ = cfgProvider.Save(origCfg)
			writeError(w, http.StatusInternalServerError, "RELOAD_FAILED", "Failed to reload configuration: "+err.Error())
			return
		}
	} else {
		if err := a.applyConfigReload(nextCfg); err != nil {
			writeError(w, http.StatusInternalServerError, "RELOAD_FAILED", "Failed to reload configuration: "+err.Error())
			return
		}
		if nextCfg != nil && cfgProvider != nil {
			if err := cfgProvider.Save(nextCfg); err != nil {
				if origCfg != nil {
					_ = a.applyConfigReload(origCfg)
				}
				writeError(w, http.StatusInternalServerError, "SAVE_FAILED", "Failed to save configuration: "+err.Error())
				return
			}
		}
	}

	a.logSecurityAudit(r, "guard_mutated", "configure", "guard", "classifier", "allowed", "AI Guard configuration updated", map[string]any{
		"mode":           req.Mode,
		"classifier_url": redactURLCredentials(targetURL),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "success",
		"classifier_url": redactURLCredentials(targetURL),
		"mode":           req.Mode,
		"message":        "AI Guard configuration successfully updated",
	})
}
