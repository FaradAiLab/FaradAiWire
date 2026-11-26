package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
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
		listenPort     = config.DefaultListenPort
		listenHost     = "127.0.0.1"
		transportMode  string
		guardCustomURL string
	)

	if cfg != nil {
		guardCustomURL = cfg.Filters.Guard.Discovery.CustomURL
		transportMode = cfg.Mode
		if cfg.GetListenPort() > 0 {
			listenPort = cfg.GetListenPort()
		}
		if cfg.GetListenHost() != "" {
			listenHost = cfg.GetListenHost()
		}
	}

	filterSummary := settings.BuildFilterStatusSummary(cfg)
	activeFilters := filterSummary.ActiveFilters
	guardEnabled := filterSummary.ConfigStates["guard"]

	gatewayID := strings.TrimSpace(os.Getenv("GATEWAY_ID"))

	customURL := ""
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
		customURL = guardEndpoint
	} else if guardEnabled {
		// Priority 2: Check external HTTP classifier / custom URL
		customURL = strings.TrimSpace(guardCustomURL)
		if customURL != "" {
			guardTier = "neural_active"
			guardStatus = "active"
			guardModel = "External HTTP Classifier"
			guardEndpoint = redactURLCredentials(customURL)
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

	configResp := make(map[string]interface{}, len(filterSummary.ConfigStates))
	for name, enabled := range filterSummary.ConfigStates {
		configResp[name] = enabled
	}

	resp := map[string]interface{}{
		"version":             config.GetVersion(),
		"active_filters":      activeFilters,
		"gateway_id":          gatewayID,
		"status":              "Ready",
		"ingress_port":        listenPort,
		"ingress_host":        listenHost,
		"ingress_url":         ingressURL,
		"transport_mode":      transportMode,
		"allow_stdio":         a.isStdioAllowed(),
		"admin_auth_required": a.isAdminAuthRequired(),
		"has_local_overrides": false,
		"guard_tier":          guardTier,
		"guard_model":         guardModel,
		"guard_endpoint":      guardEndpoint,
		"guard_latency_ms":    guardLatencyMS,
		"guard_status": map[string]interface{}{
			"tier":       guardTier,
			"custom_url": redactURLCredentials(customURL),
			"model":      guardModel,
			"active":     guardStatus == "active",
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
	return settings.ValidateGuardDiscoveryURL(rawURL)
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
	customURL := ""
	if cfg := a.Config(); cfg != nil {
		customURL = cfg.Filters.Guard.Discovery.CustomURL
	}

	// If query param or body overrides target URL (e.g. Test Connection)
	if target := strings.TrimSpace(r.URL.Query().Get("url")); target != "" {
		customURL = target
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
			customURL = strings.TrimSpace(payload.URL)
		}
	}

	if customURL != "" {
		if err := validateGuardURL(customURL); err != nil {
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
	probeRes := guardprobe.ProbeWithDiscovery(ctx, customURL, dockerURL, ollamaURL)
	probeRes.ConfiguredURL = redactURLCredentials(probeRes.ConfiguredURL)

	writeJSON(w, http.StatusOK, probeRes)
}

func (a *AdminServer) handleGuardConfigure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled   *bool   `json:"enabled"`
		Mode      string  `json:"mode"`
		OllamaURL string  `json:"ollama_url"`
		DockerURL string  `json:"docker_url"`
		CustomURL *string `json:"custom_url"`
	}
	if err := decodeJSON(w, r, maxSmallAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != "" {
		switch mode {
		case "auto", "ollama", "docker", "custom":
		default:
			writeError(w, http.StatusBadRequest, "INVALID_MODE", "Invalid guard discovery mode: must be auto, ollama, docker, or custom")
			return
		}
	}

	ollamaURL := strings.TrimSpace(req.OllamaURL)
	dockerURL := strings.TrimSpace(req.DockerURL)
	var (
		customURL    string
		setCustomURL bool
	)
	if req.CustomURL != nil {
		customURL = strings.TrimSpace(*req.CustomURL)
		setCustomURL = true
	} else if mode == "auto" || mode == "ollama" || mode == "docker" {
		// Switching away from custom mode without providing a custom_url clears any stale endpoint.
		setCustomURL = true
	}

	for _, field := range []struct {
		label string
		raw   string
	}{
		{"ollama URL", ollamaURL},
		{"docker URL", dockerURL},
		{"custom URL", customURL},
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

	ctx := r.Context()
	sStore := a.settingsStore

	pendingSettings := make(map[string]string, 5)
	if mode != "" {
		pendingSettings[settings.GuardDiscoveryModeKey] = mode
	}
	if ollamaURL != "" {
		pendingSettings[settings.GuardDiscoveryOllamaURLKey] = ollamaURL
	}
	if dockerURL != "" {
		pendingSettings[settings.GuardDiscoveryDockerURLKey] = dockerURL
	}
	if setCustomURL {
		pendingSettings[settings.GuardDiscoveryCustomURLKey] = customURL
	}
	if req.Enabled != nil {
		pendingSettings[settings.FilterKeyPrefix+"guard"] = strconv.FormatBool(*req.Enabled)
	} else if customURL != "" {
		pendingSettings[settings.FilterKeyPrefix+"guard"] = "true"
	}

	var prevOverrides map[string]string
	appliedKeys := make([]string, 0, len(pendingSettings))
	if sStore != nil && len(pendingSettings) > 0 {
		var getErr error
		prevOverrides, getErr = sStore.GetAll(ctx)
		if getErr != nil {
			slog.ErrorContext(ctx, "Failed to read prior guard settings from DuckDB", slog.String("error", getErr.Error()))
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read current guard configuration")
			return
		}

		keys := make([]string, 0, len(pendingSettings))
		for k := range pendingSettings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := sStore.Set(ctx, k, pendingSettings[k]); err != nil {
				slog.ErrorContext(ctx, "Failed to persist guard setting to DuckDB", slog.String("key", k), slog.String("error", err.Error()))
				rollbackDuckDBSettings(ctx, sStore, appliedKeys, prevOverrides)
				writeError(w, http.StatusInternalServerError, "SAVE_FAILED", "Failed to save guard configuration")
				return
			}
			appliedKeys = append(appliedKeys, k)
		}
	}

	nextCfg := a.cloneAndMutateConfig(func(c *config.Config) {
		if mode != "" {
			c.Filters.Guard.Discovery.Mode = mode
		}
		if ollamaURL != "" {
			c.Filters.Guard.Discovery.OllamaURL = ollamaURL
		}
		if dockerURL != "" {
			c.Filters.Guard.Discovery.DockerURL = dockerURL
		}
		if setCustomURL {
			c.Filters.Guard.Discovery.CustomURL = customURL
		}
		if req.Enabled != nil {
			c.Filters.Guard.Enabled = *req.Enabled
		} else if customURL != "" {
			c.Filters.Guard.Enabled = true
		}
	})

	if err := a.applyConfigReload(nextCfg); err != nil {
		slog.ErrorContext(ctx, "Failed to reload configuration after guard update", slog.String("error", err.Error()))
		rollbackDuckDBSettings(ctx, sStore, appliedKeys, prevOverrides)
		writeError(w, http.StatusInternalServerError, "RELOAD_FAILED", "Failed to reload configuration after guard update")
		return
	}

	a.logSecurityAudit(r, "guard_mutated", "configure", "guard", "discovery", "allowed", "AI Guard configuration updated", map[string]any{
		"mode":       mode,
		"custom_url": redactURLCredentials(customURL),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "success",
		"custom_url": redactURLCredentials(customURL),
		"mode":       mode,
		"message":    "AI Guard configuration successfully updated",
	})
}
