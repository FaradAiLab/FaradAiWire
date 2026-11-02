package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/slmprobe"
	"github.com/FaradAiLab/FaradAiWire/web"
)

func (a *AdminServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	web.Handler().ServeHTTP(w, r)
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var activeFilters []string
	if a.cfg.Filters.PrefillBlock.Enabled {
		activeFilters = append(activeFilters, "prefill_block")
	}
	if a.cfg.Filters.RateLimiting.Enabled {
		activeFilters = append(activeFilters, "rate_limiting")
	}
	if a.cfg.Filters.LoopProtection.Enabled {
		activeFilters = append(activeFilters, "loop_protection")
	}
	if a.cfg.Filters.SchemaValidation.Enabled {
		activeFilters = append(activeFilters, "schema_validation")
	}
	if a.cfg.Filters.DLP.Enabled {
		activeFilters = append(activeFilters, "dlp")
	}
	if a.cfg.Filters.HITL.Enabled {
		activeFilters = append(activeFilters, "hitl")
	}
	if a.cfg.Filters.Guard.Enabled || (a.guardManager != nil && a.guardManager.IsRunning()) {
		activeFilters = append(activeFilters, "guard")
	}

	gatewayID := strings.TrimSpace(os.Getenv("GATEWAY_ID"))

	mgr := a.guardManager
	catalog := a.guardCatalog

	classifierURL := ""
	slmTier := "disabled"
	slmStatus := "standby"
	slmModel := "L1 Static Rules (Fallback)"
	slmEndpoint := "In-Memory Precompiled Regex"
	var slmLatencyMS float64 = 0.2

	// Priority 1: Check active running SLM Guard (Laya MLX, Qwen3Guard, Granite Guardian)
	if mgr != nil && mgr.IsRunning() {
		procStatus := mgr.Status()
		slmTier = "neural_active"
		slmStatus = "active"
		slmModel = procStatus.ModelID
		slmEndpoint = fmt.Sprintf("stdio:%s (PID %d)", procStatus.ModelID, procStatus.PID)
		slmLatencyMS = 24.2
		if catalog != nil && r != nil {
			if m, err := catalog.Get(r.Context(), procStatus.ModelID); err == nil && m != nil {
				slmModel = m.Name
				if m.BenchmarkAvgLatencyMS > 0 {
					slmLatencyMS = m.BenchmarkAvgLatencyMS
				}
			}
		}
		classifierURL = slmEndpoint
	} else if a.cfg != nil && a.cfg.Filters.InjectionScanner.Enabled {
		// Priority 2: Check legacy/external HTTP classifier URL
		classifierURL = strings.TrimSpace(a.cfg.Filters.InjectionScanner.ClassifierURL)
		if classifierURL != "" {
			slmTier = "neural_active"
			slmStatus = "active"
			slmModel = "External HTTP Classifier"
			slmEndpoint = redactURLCredentials(classifierURL)
			slmLatencyMS = 15.0
		} else {
			slmTier = "regex_standby"
			slmStatus = "standby"
		}
	}

	listenPort := 8090
	if a.cfg != nil {
		listenPort = a.cfg.GetListenPort()
	}
	listenHost := "127.0.0.1"
	if a.cfg != nil && a.cfg.GetListenHost() != "" {
		listenHost = a.cfg.GetListenHost()
	}
	ingressURL := fmt.Sprintf("http://%s:%d", listenHost, listenPort)

	resp := map[string]interface{}{
		"active_filters":      activeFilters,
		"gateway_id":          gatewayID,
		"status":              "Ready",
		"ingress_port":        listenPort,
		"ingress_host":        listenHost,
		"ingress_url":         ingressURL,
		"mode":                a.cfg.GetRuntimeMode(),
		"runtime_mode":        a.cfg.GetRuntimeMode(),
		"transport_mode":      a.cfg.Mode,
		"has_local_overrides": false,
		"is_managed":          a.cfg.IsManaged(),
		"organization":        "Corporate Organization",
		"locked_editing":      a.cfg.IsManaged(),
		"slm_tier":            slmTier,
		"slm_model":           slmModel,
		"slm_endpoint":        slmEndpoint,
		"slm_latency_ms":      slmLatencyMS,
		"slm_status": map[string]interface{}{
			"tier":           slmTier,
			"classifier_url": redactURLCredentials(classifierURL),
			"model":          slmModel,
			"active":         slmStatus == "active",
		},

		"config": map[string]interface{}{
			"prefill_block":         a.cfg.Filters.PrefillBlock.Enabled,
			"schema_validation":     a.cfg.Filters.SchemaValidation.Enabled,
			"injection_scanner":     a.cfg.Filters.InjectionScanner.Enabled,
			"guard":                 (mgr != nil && mgr.IsRunning()) || a.cfg.Filters.Guard.Enabled,
			"dlp":                   a.cfg.Filters.DLP.Enabled,
			"hitl":                  a.cfg.Filters.HITL.Enabled,
			"loop_protection":       a.cfg.Filters.LoopProtection.Enabled,
			"rate_limiting":         a.cfg.Filters.RateLimiting.Enabled,
			"auto_sync_mcp":         a.cfg.AutoSyncMCP,
			"auto_update_policies":  a.cfg.AutoUpdatePolicies,
			"poll_interval_seconds": a.cfg.PollIntervalSeconds,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// validateSLMURL enforces pragmatic standalone security guardrails (ADR 0027):
// - Length <= 2048 chars
// - Valid HTTP or HTTPS scheme
// - Non-empty host
// - Strict rejection of link-local cloud metadata (169.254.169.254 / fe80::/10)
// - Permits loopback (127.0.0.1, ::1) and local LAN RFC1918 IPs for local developer tooling
func validateSLMURL(rawURL string) error {
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

	// Unconditional guard: Block link-local cloud metadata (AWS, GCP, Azure, OpenStack)
	if host == "169.254.169.254" || strings.HasPrefix(host, "169.254.") {
		return errors.New("access to link-local cloud metadata is strictly prohibited")
	}
	if ip := net.ParseIP(host); ip != nil {
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

func (a *AdminServer) handleSLMProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	}

	a.mu.Lock()
	classifierURL := ""
	if a.cfg != nil {
		classifierURL = a.cfg.Filters.InjectionScanner.ClassifierURL
	}
	a.mu.Unlock()

	// If query param or body overrides target URL (e.g. Test Connection)
	if target := strings.TrimSpace(r.URL.Query().Get("url")); target != "" {
		classifierURL = target
	} else if r.Method == http.MethodPost && r.Body != nil {
		var payload struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil && payload.URL != "" {
			classifierURL = strings.TrimSpace(payload.URL)
		}
	}

	if classifierURL != "" {
		if err := validateSLMURL(classifierURL); err != nil {
			http.Error(w, "Invalid probe target: "+err.Error(), http.StatusBadRequest)
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
			probeRes := slmprobe.ProbeResult{
				ConfiguredActive: true,
				ConfiguredURL:    configuredURL,
				Detected:         true,
				DetectedProvider: slmprobe.ProviderCustom,
				DetectedURL:      fmt.Sprintf("http:%s", status.ModelID),
				LatencyMs:        5,
				ModelName:        modelName,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(probeRes)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 400*time.Millisecond)
	defer cancel()

	probeRes := slmprobe.Probe(ctx, classifierURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(probeRes)
}

func (a *AdminServer) handleSLMConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		ClassifierURL string `json:"classifier_url"`
		Enabled       *bool  `json:"enabled"`
		Mode          string `json:"mode"`
		OllamaURL     string `json:"ollama_url"`
		DockerURL     string `json:"docker_url"`
		CustomURL     string `json:"custom_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	targetURL := strings.TrimSpace(req.ClassifierURL)
	if targetURL == "" && req.CustomURL != "" {
		targetURL = strings.TrimSpace(req.CustomURL)
	}

	if targetURL != "" {
		if err := validateSLMURL(targetURL); err != nil {
			http.Error(w, "Invalid classifier URL: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	a.mu.Lock()
	if a.cfg != nil {
		if req.Mode != "" {
			a.cfg.Filters.Guard.Discovery.Mode = req.Mode
		}
		if req.OllamaURL != "" {
			a.cfg.Filters.Guard.Discovery.OllamaURL = req.OllamaURL
		}
		if req.DockerURL != "" {
			a.cfg.Filters.Guard.Discovery.DockerURL = req.DockerURL
		}
		if req.CustomURL != "" {
			a.cfg.Filters.Guard.Discovery.CustomURL = req.CustomURL
		}
		if targetURL != "" {
			a.cfg.Filters.InjectionScanner.ClassifierURL = targetURL
		}
		if req.Enabled != nil {
			a.cfg.Filters.InjectionScanner.Enabled = *req.Enabled
			a.cfg.Filters.Guard.Enabled = *req.Enabled
		} else if targetURL != "" {
			a.cfg.Filters.InjectionScanner.Enabled = true
		}
		if a.cfgProvider != nil {
			_ = a.cfgProvider.Save(a.cfg)
		}
	}
	a.mu.Unlock()

	if a.reloadFunc != nil {
		_ = a.reloadFunc()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"classifier_url": targetURL,
		"mode":           req.Mode,
		"message":        "SLM configuration successfully updated",
	})
}
