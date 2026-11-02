package slmprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxProbeTimeout is the strict upper bound for all probe operations.
	DefaultMaxProbeTimeout = 300 * time.Millisecond

	// DefaultPromptGuardHealthURL is the standard health endpoint for the Farad Ai prompt-guard sidecar.
	DefaultPromptGuardHealthURL = "http://127.0.0.1:8088/health"

	// DefaultPromptGuardPredictURL is the standard predict endpoint for prompt-guard.
	DefaultPromptGuardPredictURL = "http://127.0.0.1:8088/predict"

	// DefaultOllamaTagsURL is the standard tags endpoint for local Ollama.
	DefaultOllamaTagsURL = "http://127.0.0.1:11434/api/tags"

	// DefaultOllamaBaseURL is the standard base URL for local Ollama.
	DefaultOllamaBaseURL = "http://127.0.0.1:11434"
)

// Prober orchestrates non-blocking discovery of local and configured SLM instances.
type Prober struct {
	client              *http.Client
	timeout             time.Duration
	promptGuardHealthURL string
	promptGuardPredictURL string
	ollamaTagsURL       string
	ollamaBaseURL       string
}

// Option allows customizing Prober parameters (e.g. for testing with mock servers).
type Option func(*Prober)

// WithHTTPClient overrides the HTTP client used for probing.
func WithHTTPClient(client *http.Client) Option {
	return func(p *Prober) {
		if client != nil {
			p.client = client
		}
	}
}

// WithTimeout overrides the probe timeout duration.
func WithTimeout(d time.Duration) Option {
	return func(p *Prober) {
		if d > 0 {
			p.timeout = d
		}
	}
}

// WithPromptGuardURL overrides the prompt-guard probe endpoints.
func WithPromptGuardURL(healthURL, predictURL string) Option {
	return func(p *Prober) {
		if healthURL != "" {
			p.promptGuardHealthURL = healthURL
		}
		if predictURL != "" {
			p.promptGuardPredictURL = predictURL
		}
	}
}

// WithOllamaURL overrides the Ollama probe endpoints.
func WithOllamaURL(tagsURL, baseURL string) Option {
	return func(p *Prober) {
		if tagsURL != "" {
			p.ollamaTagsURL = tagsURL
		}
		if baseURL != "" {
			p.ollamaBaseURL = baseURL
		}
	}
}

// NewProber initializes a Prober with sensible defaults.
func NewProber(opts ...Option) *Prober {
	p := &Prober{
		client: &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				MaxIdleConns:      10,
				IdleConnTimeout:   1 * time.Second,
			},
		},
		timeout:              DefaultMaxProbeTimeout,
		promptGuardHealthURL: DefaultPromptGuardHealthURL,
		promptGuardPredictURL: DefaultPromptGuardPredictURL,
		ollamaTagsURL:        DefaultOllamaTagsURL,
		ollamaBaseURL:        DefaultOllamaBaseURL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// DefaultProber is the package-level singleton used by Probe().
var DefaultProber = NewProber()

// Probe invokes discovery on the default prober instance.
func Probe(ctx context.Context, configuredURL string) *ProbeResult {
	return DefaultProber.Probe(ctx, configuredURL)
}

// Probe asynchronously inspects candidate local SLMs and the configured URL within a bounded deadline.
func (p *Prober) Probe(ctx context.Context, configuredURL string) *ProbeResult {
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	result := &ProbeResult{
		ConfiguredURL:    strings.TrimSpace(configuredURL),
		DetectedProvider: ProviderNone,
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup

		cfgActive  bool
		cfgLatency int64
		cfgModel   string

		pgActive  bool
		pgLatency int64
		pgModel   string

		ollamaActive  bool
		ollamaLatency int64
		ollamaModel   string
	)

	// 1. Probe configured URL if provided
	if result.ConfiguredURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			active, latency, model := p.probeConfigured(probeCtx, result.ConfiguredURL)
			if active {
				mu.Lock()
				cfgActive = true
				cfgLatency = latency
				cfgModel = model
				mu.Unlock()
			}
		}()
	}

	// 2. Probe Prompt-Guard Docker sidecar convention
	wg.Add(1)
	go func() {
		defer wg.Done()
		active, latency, model := p.probePromptGuard(probeCtx, p.promptGuardHealthURL)
		if active {
			mu.Lock()
			pgActive = true
			pgLatency = latency
			pgModel = model
			mu.Unlock()
		}
	}()

	// 3. Probe Ollama convention
	wg.Add(1)
	go func() {
		defer wg.Done()
		active, latency, model := p.probeOllama(probeCtx, p.ollamaTagsURL)
		if active {
			mu.Lock()
			ollamaActive = true
			ollamaLatency = latency
			ollamaModel = model
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Reconcile configured status
	if cfgActive {
		result.ConfiguredActive = true
		result.LatencyMs = cfgLatency
		result.ModelName = cfgModel
	}

	// Reconcile auto-detected status deterministically (Docker / Prompt-Guard takes precedence)
	if pgActive {
		result.Detected = true
		if pgModel == "FaradAiGuard (Docker)" {
			result.DetectedProvider = ProviderDocker
			result.DetectedURL = "http://127.0.0.1:8088"
		} else {
			result.DetectedProvider = ProviderPromptGuard
			result.DetectedURL = p.promptGuardPredictURL
		}
		if result.LatencyMs == 0 {
			result.LatencyMs = pgLatency
		}
		if result.ModelName == "" {
			result.ModelName = pgModel
		}
	} else if ollamaActive {
		result.Detected = true
		result.DetectedProvider = ProviderOllama
		result.DetectedURL = p.ollamaBaseURL
		if result.LatencyMs == 0 {
			result.LatencyMs = ollamaLatency
		}
		if result.ModelName == "" {
			result.ModelName = ollamaModel
		}
	}

	return result
}

func (p *Prober) probePromptGuard(ctx context.Context, healthURL string) (bool, int64, string) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false, 0, ""
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false, 0, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, ""
	}

	var health promptGuardHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err == nil && (health.Status == "healthy" || health.Status == "ok") {
		elapsed := time.Since(start).Milliseconds()
		model := health.Model
		if model == "" {
			model = "FaradAiGuard (Docker)"
		}
		return true, elapsed, model
	}

	return true, time.Since(start).Milliseconds(), "FaradAiGuard (Docker)"
}

func (p *Prober) probeOllama(ctx context.Context, tagsURL string) (bool, int64, string) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
	if err != nil {
		return false, 0, ""
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false, 0, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, ""
	}

	var tags ollamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err == nil {
		elapsed := time.Since(start).Milliseconds()
		var modelName string
		if len(tags.Models) > 0 {
			modelName = tags.Models[0].Name
		}
		return true, elapsed, modelName
	}

	return true, time.Since(start).Milliseconds(), ""
}

func (p *Prober) probeConfigured(ctx context.Context, targetURL string) (bool, int64, string) {
	// Attempt health check if target looks like prompt-guard endpoint
	if strings.HasSuffix(targetURL, "/predict") {
		healthURL := strings.TrimSuffix(targetURL, "/predict") + "/health"
		if ok, lat, model := p.probePromptGuard(ctx, healthURL); ok {
			return true, lat, model
		}
	}

	// Fallback: Perform minimal POST request to the configured classifier endpoint
	start := time.Now()
	reqBody, _ := json.Marshal(map[string]string{"text": "ping"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return false, 0, ""
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		// As a secondary fallback, try GET (e.g. if targetURL is base Ollama)
		getReq, getErr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if getErr == nil {
			if getResp, err2 := p.client.Do(getReq); err2 == nil {
				defer getResp.Body.Close()
				if getResp.StatusCode >= 200 && getResp.StatusCode < 400 {
					return true, time.Since(start).Milliseconds(), ""
				}
			}
		}
		return false, 0, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, time.Since(start).Milliseconds(), ""
	}

	return false, 0, ""
}
