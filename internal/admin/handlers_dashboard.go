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

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/slmprobe"
	"github.com/FaradAiLab/FaradAiWire/web"
)

func (a *AdminServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	web.Handler().ServeHTTP(w, r)
}

func (a *AdminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	cfg := a.cfg
	mgr := a.guardManager
	catalog := a.guardCatalog
	a.mu.RUnlock()

	var (
		activeFilters      []string
		listenPort         = 8090
		listenHost         = "127.0.0.1"
		runtimeMode        string
		transportMode      string
		isManaged          bool
		injScannerEnabled  bool
		injClassifierURL   string
		prefillEnabled     bool
		schemaEnabled      bool
		guardEnabled       bool
		dlpEnabled         bool
		hitlEnabled        bool
		loopEnabled        bool
		rateLimitEnabled   bool
		autoSyncMCP        bool
		autoUpdatePolicies bool
		pollIntervalSec    int
	)

	if cfg != nil {
		prefillEnabled = cfg.Filters.PrefillBlock.Enabled
		rateLimitEnabled = cfg.Filters.RateLimiting.Enabled
		loopEnabled = cfg.Filters.LoopProtection.Enabled
		schemaEnabled = cfg.Filters.SchemaValidation.Enabled
		dlpEnabled = cfg.Filters.DLP.Enabled
		hitlEnabled = cfg.Filters.HITL.Enabled
		guardEnabled = cfg.Filters.Guard.Enabled
		injScannerEnabled = cfg.Filters.InjectionScanner.Enabled
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

	if prefillEnabled {
		activeFilters = append(activeFilters, "prefill_block")
	}
	if rateLimitEnabled {
		activeFilters = append(activeFilters, "rate_limiting")
	}
	if loopEnabled {
		activeFilters = append(activeFilters, "loop_protection")
	}
	if schemaEnabled {
		activeFilters = append(activeFilters, "schema_validation")
	}
	if dlpEnabled {
		activeFilters = append(activeFilters, "dlp")
	}
	if hitlEnabled {
		activeFilters = append(activeFilters, "hitl")
	}
	if guardEnabled {
		activeFilters = append(activeFilters, "guard")
	}

	gatewayID := strings.TrimSpace(os.Getenv("GATEWAY_ID"))

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
	} else if injScannerEnabled {
		// Priority 2: Check legacy/external HTTP classifier URL
		classifierURL = strings.TrimSpace(injClassifierURL)
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

	ingressURL := fmt.Sprintf("http://%s:%d", listenHost, listenPort)

	resp := map[string]interface{}{
		"active_filters":      activeFilters,
		"gateway_id":          gatewayID,
		"status":              "Ready",
		"ingress_port":        listenPort,
		"ingress_host":        listenHost,
		"ingress_url":         ingressURL,
		"mode":                runtimeMode,
		"runtime_mode":        runtimeMode,
		"transport_mode":      transportMode,
		"has_local_overrides": false,
		"is_managed":          isManaged,
		"organization":        "Corporate Organization",
		"locked_editing":      isManaged,
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
			"prefill_block":         prefillEnabled,
			"schema_validation":     schemaEnabled,
			"injection_scanner":     injScannerEnabled,
			"guard":                 guardEnabled,
			"dlp":                   dlpEnabled,
			"hitl":                  hitlEnabled,
			"loop_protection":       loopEnabled,
			"rate_limiting":         rateLimitEnabled,
			"auto_sync_mcp":         autoSyncMCP,
			"auto_update_policies":  autoUpdatePolicies,
			"poll_interval_seconds": pollIntervalSec,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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
			_ = json.NewEncoder(w).Encode(probeRes)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 400*time.Millisecond)
	defer cancel()

	probeRes := slmprobe.Probe(ctx, classifierURL)
	probeRes.ConfiguredURL = redactURLCredentials(probeRes.ConfiguredURL)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(probeRes)
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
			if err := validateSLMURL(field.raw); err != nil {
				http.Error(w, "Invalid "+field.label+": "+err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	a.configMutMu.Lock()
	defer a.configMutMu.Unlock()

	applySLMMutation := func(cfg *config.Config) {
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

	a.mu.RLock()
	origCfg := a.cfg
	cfgProvider := a.cfgProvider
	reloadCfgFn := a.reloadConfigFunc
	reloadFn := a.reloadFunc
	var nextCfg *config.Config
	if origCfg != nil {
		nextCfg = origCfg.Clone()
	}
	a.mu.RUnlock()

	if nextCfg != nil {
		applySLMMutation(nextCfg)
	}

	if reloadCfgFn == nil && reloadFn != nil && nextCfg != nil && cfgProvider != nil {
		if err := cfgProvider.Save(nextCfg); err != nil {
			http.Error(w, "Failed to save configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.applyConfigReload(nextCfg); err != nil {
			_ = cfgProvider.Save(origCfg)
			http.Error(w, "Failed to reload configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := a.applyConfigReload(nextCfg); err != nil {
			http.Error(w, "Failed to reload configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if nextCfg != nil && cfgProvider != nil {
			if err := cfgProvider.Save(nextCfg); err != nil {
				if origCfg != nil {
					_ = a.applyConfigReload(origCfg)
				}
				http.Error(w, "Failed to save configuration: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "success",
		"classifier_url": redactURLCredentials(targetURL),
		"mode":           req.Mode,
		"message":        "SLM configuration successfully updated",
	})
}
