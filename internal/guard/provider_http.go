package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPProviderConfig specifies configuration parameters for the HTTP inference provider.
type HTTPProviderConfig struct {
	BaseURL         string        // Base endpoint, e.g. "http://127.0.0.1:11434" or "http://127.0.0.1:8088"
	ModelName       string        // Target model name or registry reference
	TimeoutSLA      time.Duration // Enforced hot-path execution timeout (default: 1s)
	ColdTimeoutSLA  time.Duration // Enforced cold-path execution timeout for initial or idle requests (default: 3s)
	IdleWarmWindow  time.Duration // Inactivity duration after which model is considered cold (default: 4m)
	MaxConcurrency  int           // Bounded concurrency semaphore slots (default: 8)
	MaxIdleConns    int           // HTTP transport connection pool capacity (default: 20)
	IdleConnTimeout time.Duration // Maximum idle connection duration (default: 30s)
	UseOllamaAPI    bool          // If true uses /api/chat; otherwise standard /v1/chat/completions
}

// DefaultHTTPProviderConfig returns recommended production parameters per ADR-0041.
func DefaultHTTPProviderConfig() HTTPProviderConfig {
	return HTTPProviderConfig{
		BaseURL:         "http://127.0.0.1:11434",
		ModelName:       "hf.co/faradailab/guard-qwen3guard",
		TimeoutSLA:      1 * time.Second,
		ColdTimeoutSLA:  3 * time.Second,
		IdleWarmWindow:  4 * time.Minute,
		MaxConcurrency:  8,
		MaxIdleConns:    20,
		IdleConnTimeout: 30 * time.Second,
		UseOllamaAPI:    false,
	}
}

// HTTPProvider implements the Manager interface communicating with an external
// SLM inference provider (Ollama or llama-server container) over HTTP REST.
type HTTPProvider struct {
	cfg           HTTPProviderConfig
	client        *http.Client
	sem           chan struct{}
	mu            sync.RWMutex
	model         *Model
	running       bool
	startedAt     time.Time
	lastSuccessAt time.Time
	healthStat    string
	inferenceMode string // "chat", "generate", "systemone", or "" (auto-detect)
}

// NewHTTPProvider constructs a thread-safe, connection-pooled HTTP provider.
// An optional custom *http.Client can be injected for testing or specialized transports.
func NewHTTPProvider(cfg HTTPProviderConfig, httpClient ...*http.Client) *HTTPProvider {
	if cfg.TimeoutSLA <= 0 {
		cfg.TimeoutSLA = 1 * time.Second
	}
	if cfg.ColdTimeoutSLA <= 0 {
		cfg.ColdTimeoutSLA = cfg.TimeoutSLA
	}
	if cfg.IdleWarmWindow <= 0 {
		cfg.IdleWarmWindow = 4 * time.Minute
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 8
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = 20
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = 30 * time.Second
	}

	var client *http.Client
	if len(httpClient) > 0 && httpClient[0] != nil {
		client = httpClient[0]
	} else {
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   500 * time.Millisecond,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          cfg.MaxIdleConns,
			MaxIdleConnsPerHost:   cfg.MaxIdleConns,
			IdleConnTimeout:       cfg.IdleConnTimeout,
			TLSHandshakeTimeout:   500 * time.Millisecond,
			ExpectContinueTimeout: 100 * time.Millisecond,
		}
		client = &http.Client{
			Transport: transport,
		}
	}

	return &HTTPProvider{
		cfg:        cfg,
		client:     client,
		sem:        make(chan struct{}, cfg.MaxConcurrency),
		healthStat: "STOPPED",
	}
}

// Start binds an active Model and transitions the provider to running status.
func (p *HTTPProvider) Start(ctx context.Context, model *Model) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.model = model
	if model != nil {
		if model.EndpointURL != "" {
			p.cfg.BaseURL = model.EndpointURL
		}
		if model.RuntimeType == "ollama" {
			p.cfg.UseOllamaAPI = true
		} else if model.RuntimeType == "docker" {
			p.cfg.UseOllamaAPI = false
		}
		if model.OllamaSource != "" {
			p.cfg.ModelName = model.OllamaSource
		} else if model.DockerImage != "" {
			p.cfg.ModelName = model.DockerImage
		} else if model.ID != "" {
			p.cfg.ModelName = model.ID
		}
	}

	p.inferenceMode = "" // Reset mode on new model
	p.running = true
	p.startedAt = time.Now()
	p.healthStat = "HEALTHY"

	// Pre-Flight Capability Probe (ADR-0046) in background
	go p.probeCapability(context.Background())
	return nil
}

// StartScript provides compatibility with the Manager interface without launching host subprocesses.
func (p *HTTPProvider) StartScript(ctx context.Context, scriptPath string, modelID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.running = true
	p.startedAt = time.Now()
	p.healthStat = "HEALTHY"
	if modelID != "" {
		p.cfg.ModelName = modelID
	}
	p.inferenceMode = "" // Reset mode on new script/model
	return nil
}

// Stop shuts down the provider and marks status stopped.
func (p *HTTPProvider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.running = false
	p.healthStat = "STOPPED"
	return nil
}

// IsRunning reports whether the HTTP provider is active and ready for calls.
func (p *HTTPProvider) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// Status returns runtime diagnostic telemetry for the Web Console and CLI.
func (p *HTTPProvider) Status() ProcessStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	modelID := p.cfg.ModelName
	if p.model != nil && p.model.ID != "" {
		modelID = p.model.ID
	}

	var started *time.Time
	if !p.startedAt.IsZero() {
		started = &p.startedAt
	}

	return ProcessStatus{
		Running:      p.running,
		ModelID:      modelID,
		PID:          0,
		MemoryRSSMB:  0,
		HealthStatus: p.healthStat,
		StartedAt:    started,
	}
}

// postJSON executes a POST request with JSON content-type and returns the status code and bounded response body.
// It uniformly handles deadline expiration and guarantees connection reuse by draining and closing the body.
func (p *HTTPProvider) postJSON(ctx context.Context, targetURL string, payload any) (int, []byte, error) {
	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 0, nil, fmt.Errorf("%w: %v", ErrTimeout, err)
		}
		return 0, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp.StatusCode, bodyBytes, nil
}

// endpointURL resolves the full URL for a target path, respecting pre-configured endpoint overrides.
func (p *HTTPProvider) endpointURL(path string) string {
	baseURL := strings.TrimRight(p.cfg.BaseURL, "/")
	if strings.HasSuffix(baseURL, path) {
		return baseURL
	}
	if path == "/v1/chat/completions" && strings.Contains(baseURL, "/chat/completions") {
		return baseURL
	}
	for _, suffix := range []string{"/api/chat", "/api/generate", "/v1/chat/completions", "/chat/completions", "/v1/systemone"} {
		if strings.HasSuffix(baseURL, suffix) {
			baseURL = strings.TrimSuffix(baseURL, suffix)
			break
		}
	}
	return baseURL + path
}

// validateURL verifies that the endpoint URL scheme is supported (SSRF defense).
func validateURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("invalid http provider base URL '%s': only http/https supported", rawURL)
	}
	return nil
}

func parseParameterSizeInBillions(sizeStr string) float64 {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))
	if strings.HasSuffix(sizeStr, "M") {
		numStr := strings.TrimSuffix(sizeStr, "M")
		if val, err := strconv.ParseFloat(strings.TrimSpace(numStr), 64); err == nil {
			return val / 1000.0 // in billions
		}
	}
	if strings.HasSuffix(sizeStr, "B") {
		numStr := strings.TrimSuffix(sizeStr, "B")
		if val, err := strconv.ParseFloat(strings.TrimSpace(numStr), 64); err == nil {
			return val
		}
	}
	if val, err := strconv.ParseFloat(sizeStr, 64); err == nil {
		return val
	}
	return 0.0
}

// calculateAdaptiveSLA determines the hot and cold Timeout SLA based on the active model specification.
// Models <= 2.0B receive 1.0s hot SLA (3.0s cold) by default.
// Heavyweight 3B-4B models (e.g. Liquid 3B, Perplexity 4B, Mica 4B) receive 2.5s hot SLA (5.0s cold)
// to prevent premature L1 degradation during heavy reasoning or disk paging.
func calculateAdaptiveSLA(model *Model, defaultHot, defaultCold time.Duration) (time.Duration, time.Duration) {
	hot := defaultHot
	if hot <= 0 {
		hot = 1 * time.Second
	}
	cold := defaultCold
	if cold <= 0 {
		cold = 3 * time.Second
	}

	if model == nil {
		return hot, cold
	}

	isHeavyweight := false
	billions := parseParameterSizeInBillions(model.ParameterSize)
	if billions >= 3.0 {
		isHeavyweight = true
	}
	if model.ID == "liquid-d1" || model.ID == "pplx-decider-flash" || model.ID == "mica-v0.5" {
		isHeavyweight = true
	}

	if isHeavyweight {
		if hot < 2500*time.Millisecond && (defaultHot == DefaultHTTPProviderConfig().TimeoutSLA || defaultHot == 0) {
			hot = 2500 * time.Millisecond
		}
		if cold < 5000*time.Millisecond && (defaultCold == DefaultHTTPProviderConfig().ColdTimeoutSLA || defaultCold == 0) {
			cold = 5000 * time.Millisecond
		}
	}

	return hot, cold
}

// selectGenerativeEngine selects the appropriate generative inference engine strategy.
func (p *HTTPProvider) selectGenerativeEngine(baseURL string, curMode string, useOllama bool, contextWindow int) InferenceEngine {
	if curMode == "generate" && useOllama {
		return &OllamaGenerateEngine{ContextWindow: contextWindow}
	}
	parsedURL, _ := url.Parse(baseURL)
	if useOllama || (parsedURL != nil && strings.HasSuffix(parsedURL.Path, "/api/chat")) {
		return &OllamaChatEngine{ContextWindow: contextWindow}
	}
	return &OpenAIChatEngine{}
}

// executeSystemOneInference evaluates tool invocation parameters against Ollama's /v1/systemone
// decision endpoint using FaradAiBenchmark's calibrated Dual-Check questions and tiered thresholds.
func (p *HTTPProvider) executeSystemOneInference(
	ctx context.Context,
	targetURL string,
	modelName string,
	req *InspectionRequest,
	start time.Time,
	contextWindow int,
) (*InspectionResult, error) {
	engine := &SystemOneEngine{ContextWindow: contextWindow}
	payload, err := engine.BuildPayload(modelName, req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal systemone request: %w", err)
	}

	statusCode, bodyBytes, err := p.postJSON(ctx, targetURL, payload)
	if err != nil {
		if errors.Is(err, ErrTimeout) {
			return nil, err
		}
		return nil, fmt.Errorf("systemone http call failed: %w", err)
	}

	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("systemone returned status %d: %s", statusCode, string(bodyBytes))
	}

	latencyMS := float64(time.Since(start).Microseconds()) / 1000.0
	return engine.ParseResponse(bodyBytes, latencyMS, modelName)
}

// isChatTemplateError checks whether an Ollama HTTP 400 error indicates missing chat template or raw completion model.
// Optimized for zero heap allocations by scanning byte slices directly.
func isChatTemplateError(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	return bytes.Contains(lower, []byte("does not support chat")) ||
		bytes.Contains(lower, []byte("template")) ||
		bytes.Contains(lower, []byte("chat template")) ||
		bytes.Contains(lower, []byte("prompt template"))
}

// handleOllamaChatFallback handles Ollama models lacking chat templates (ADR-0046 & ADR-0047).
// It tests SystemOne first for ModernBERT models, then falls back to /api/generate.
func (p *HTTPProvider) handleOllamaChatFallback(
	ctx context.Context,
	modelName string,
	req *InspectionRequest,
	start time.Time,
	contextWindow int,
) (*InspectionResult, error) {
	// 1. First probe /v1/systemone (for ModernBERT Decision Models like Laya).
	sysURL := p.endpointURL("/v1/systemone")
	if sysRes, sErr := p.executeSystemOneInference(ctx, sysURL, modelName, req, start, contextWindow); sErr == nil {
		p.mu.Lock()
		p.inferenceMode = "systemone"
		p.mu.Unlock()
		slog.InfoContext(ctx, "Ollama model identified as SystemOne Decision Model; pre-configured systemone adapter",
			slog.String("model", modelName),
		)
		return sysRes, nil
	}

	// 2. If systemone fails, fall back to /api/generate (for Causal LLMs lacking chat template).
	slog.InfoContext(ctx, "Ollama model lacks chat template; executing Dual-Mode fallback to /api/generate",
		slog.String("model", modelName),
	)

	genEngine := &OllamaGenerateEngine{ContextWindow: contextWindow}
	genURL := p.endpointURL(genEngine.EndpointPath())
	genPayload, err := genEngine.BuildPayload(modelName, req)
	if err != nil {
		return nil, err
	}

	genStatus, genBody, genErr := p.postJSON(ctx, genURL, genPayload)
	if genErr == nil && genStatus >= 200 && genStatus < 300 {
		p.mu.Lock()
		p.inferenceMode = "generate"
		p.mu.Unlock()
		latencyMS := float64(time.Since(start).Microseconds()) / 1000.0
		return genEngine.ParseResponse(genBody, latencyMS, modelName)
	}

	if genErr != nil {
		return nil, fmt.Errorf("http inference call failed: %w", genErr)
	}
	return nil, fmt.Errorf("http inference returned status %d: %s", genStatus, string(genBody))
}

// CallInspect evaluates an MCP tool call request against the remote SLM inference provider.
func (p *HTTPProvider) CallInspect(ctx context.Context, req *InspectionRequest) (res *InspectionResult, err error) {
	defer func() {
		if err == nil && res != nil {
			p.mu.Lock()
			p.lastSuccessAt = time.Now()
			p.mu.Unlock()
		}
	}()

	// 1. Thread-safe state snapshot
	p.mu.RLock()
	if !p.running {
		p.mu.RUnlock()
		return nil, ErrProcessNotRunning
	}
	baseURL := p.cfg.BaseURL
	modelName := p.cfg.ModelName
	var paradigm ModelParadigm = ModelParadigmGenerativeLLM
	contextWindow := 2048
	if p.model != nil {
		if p.model.OllamaSource != "" {
			modelName = p.model.OllamaSource
		} else if p.model.DockerImage != "" {
			modelName = p.model.DockerImage
		} else if p.model.ID != "" {
			modelName = p.model.ID
		}
		if p.model.Paradigm != "" {
			paradigm = p.model.Paradigm
		}
		if p.model.ContextWindow > 0 {
			contextWindow = p.model.ContextWindow
		}
	}
	hotSLA, coldSLA := calculateAdaptiveSLA(p.model, p.cfg.TimeoutSLA, p.cfg.ColdTimeoutSLA)
	isCold := p.lastSuccessAt.IsZero() || time.Since(p.lastSuccessAt) > p.cfg.IdleWarmWindow
	timeoutSLA := hotSLA
	if isCold && coldSLA > 0 {
		timeoutSLA = coldSLA
	}
	useOllama := p.cfg.UseOllamaAPI || strings.Contains(baseURL, "11434")
	curMode := p.inferenceMode
	p.mu.RUnlock()

	// 2. Validate URL (prevent SSRF and unsupported schemes)
	if err := validateURL(baseURL); err != nil {
		return nil, err
	}

	// 3. Concurrency Semaphore: bounded non-blocking acquisition for load shedding
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	default:
		return nil, ErrQueueFull
	}

	// 4. Enforce SLA Timeout Context
	if timeoutSLA > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutSLA)
		defer cancel()
	}

	start := time.Now()

	// 5. Direct Paradigm Routing: Decision Models route straight to SystemOne
	if (paradigm == ModelParadigmDecisionModel && curMode != "generate" && curMode != "chat") || curMode == "systemone" {
		targetURL := p.endpointURL("/v1/systemone")
		res, err := p.executeSystemOneInference(ctx, targetURL, modelName, req, start, contextWindow)
		if err == nil {
			return res, nil
		}
		// If SystemOne endpoint is unavailable (e.g. 404 from standard Ollama daemon):
		// Do NOT hard-exit to L1 (prevents Silent Fail-Open).
		// Gracefully degrade to structured chat/generate fallback and cache mode in memory
		// to avoid recurring 404 latency penalties on subsequent calls.
		slog.WarnContext(ctx, "SystemOne endpoint unavailable; falling through to structured Ollama fallback",
			slog.String("model", modelName),
			slog.String("endpoint", targetURL),
			slog.String("degraded_mode", "GENERATIVE_FALLBACK"),
			slog.String("error", err.Error()),
		)
		p.mu.Lock()
		p.inferenceMode = "generate"
		p.mu.Unlock()
		curMode = "generate"
	}

	// 6. Select generative engine strategy
	engine := p.selectGenerativeEngine(baseURL, curMode, useOllama, contextWindow)
	targetURL := p.endpointURL(engine.EndpointPath())
	payload, err := engine.BuildPayload(modelName, req)
	if err != nil {
		return nil, err
	}

	statusCode, bodyBytes, err := p.postJSON(ctx, targetURL, payload)
	if err != nil {
		return nil, fmt.Errorf("http inference call failed: %w", err)
	}

	// 7. Dual-Mode Guard Fallback (ADR-0046 & ADR-0047):
	// If Ollama returned status 400 because the model lacks chat template:
	if statusCode == http.StatusBadRequest && useOllama && isChatTemplateError(bodyBytes) {
		p.mu.Lock()
		p.inferenceMode = "generate"
		p.mu.Unlock()
		return p.handleOllamaChatFallback(ctx, modelName, req, start, contextWindow)
	}

	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("http inference returned status %d: %s", statusCode, string(bodyBytes))
	}

	latencyMS := float64(time.Since(start).Microseconds()) / 1000.0
	return engine.ParseResponse(bodyBytes, latencyMS, modelName)
}

// probeCapability performs an asynchronous pre-flight probe against an Ollama endpoint
// to detect if the active model supports /api/chat or requires /api/generate fallback (ADR-0046).
func (p *HTTPProvider) probeCapability(ctx context.Context) {
	p.mu.RLock()
	baseURL := p.cfg.BaseURL
	modelName := p.cfg.ModelName
	useOllama := p.cfg.UseOllamaAPI || strings.Contains(baseURL, "11434")
	p.mu.RUnlock()

	if !useOllama || modelName == "" {
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	chatPayload := map[string]interface{}{
		"model": modelName,
		"messages": []map[string]string{
			{"role": "user", "content": "ping"},
		},
		"stream": false,
	}

	status, body, err := p.postJSON(probeCtx, p.endpointURL("/api/chat"), chatPayload)
	if err != nil {
		return
	}

	if status == http.StatusBadRequest && isChatTemplateError(body) {
		// Probe SystemOne first for ModernBERT decision models
		testSysReq := systemOneRequest{
			Model:     modelName,
			State:     "PRIMARY_USER_GOAL: Ping\nTOOL_NAME: ping\nCALL_ARGUMENTS: {}",
			Questions: dualCheckQuestions,
		}
		sysStatus, _, sysErr := p.postJSON(probeCtx, p.endpointURL("/v1/systemone"), testSysReq)
		if sysErr == nil && sysStatus >= 200 && sysStatus < 300 {
			p.mu.Lock()
			p.inferenceMode = "systemone"
			p.lastSuccessAt = time.Now()
			p.mu.Unlock()
			slog.Info("Pre-flight probe detected Ollama SystemOne Decision Model; pre-configured systemone adapter",
				slog.String("model", modelName),
			)
			return
		}

		p.mu.Lock()
		p.inferenceMode = "generate"
		p.lastSuccessAt = time.Now()
		p.mu.Unlock()
		slog.Info("Pre-flight probe detected Ollama completion-only model; pre-configured Dual-Mode generate adapter",
			slog.String("model", modelName),
		)
		return
	}

	if status >= 200 && status < 300 {
		p.mu.Lock()
		p.inferenceMode = "chat"
		p.lastSuccessAt = time.Now()
		p.mu.Unlock()
	}
}
