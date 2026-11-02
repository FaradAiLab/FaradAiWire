package slmprobe

// ProviderType represents the class of SLM inference provider detected or configured.
type ProviderType string

const (
	ProviderPromptGuard ProviderType = "prompt-guard"
	ProviderDocker      ProviderType = "docker"
	ProviderOllama      ProviderType = "ollama"
	ProviderCustom      ProviderType = "custom"
	ProviderNone        ProviderType = "none"
)

// ProbeResult captures the discovery and health status of local and configured SLMs.
type ProbeResult struct {
	ConfiguredActive bool         `json:"configured_active"`
	ConfiguredURL    string       `json:"configured_url"`
	Detected         bool         `json:"detected"`
	DetectedProvider ProviderType `json:"detected_provider"`
	DetectedURL      string       `json:"detected_url"`
	LatencyMs        int64        `json:"latency_ms"`
	ModelName        string       `json:"model_name"`
	ErrorMessage     string       `json:"error_message,omitempty"`
}

// promptGuardHealthResponse models the JSON payload from the prompt-guard sidecar /health endpoint.
type promptGuardHealthResponse struct {
	Status string `json:"status"`
	Model  string `json:"model"`
}

// ollamaTagsResponse models the JSON payload from Ollama's /api/tags endpoint.
type ollamaTagsResponse struct {
	Models []struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	} `json:"models"`
}
