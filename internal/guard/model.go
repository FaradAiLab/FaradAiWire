package guard

import (
	"encoding/json"
	"time"
)

// InstallStatus defines the runtime deployment state of an SLM guard.
type InstallStatus string

const (
	InstallStatusNotInstalled InstallStatus = "NOT_INSTALLED"
	InstallStatusInstalling   InstallStatus = "INSTALLING"
	InstallStatusInstalled    InstallStatus = "INSTALLED"
	InstallStatusFailed       InstallStatus = "FAILED"
)

// ThreatAction defines the enforcement action taken upon threat detection.
type ThreatAction string

const (
	ThreatActionHITL  ThreatAction = "hitl"
	ThreatActionBlock ThreatAction = "block"
)

// ModelParadigm defines the operational category of an SLM security guard.
type ModelParadigm string

const (
	// ModelParadigmGenerativeLLM indicates an autoregressive generative model evaluated via /api/chat or /api/generate.
	ModelParadigmGenerativeLLM ModelParadigm = "generative_llm"
	// ModelParadigmDecisionModel indicates an encoder / sequence classifier model evaluated via /v1/systemone.
	ModelParadigmDecisionModel ModelParadigm = "decision_model"
)

// Model represents a curated SLM security guard in the DuckDB Model Catalog.
type Model struct {
	ID                    string        `json:"id"`
	Name                  string        `json:"name"`
	Family                string        `json:"family"`
	Paradigm              ModelParadigm `json:"paradigm"`
	ParameterSize         string        `json:"parameter_size"`
	RAMRequiredMB         int           `json:"ram_required_mb"`
	DiskSizeMB            int           `json:"disk_size_mb"`
	Description           string        `json:"description"`
	RecommendedFor        string        `json:"recommended_for"`
	BenchmarkAccuracy     float64       `json:"benchmark_accuracy"`
	BenchmarkFPRate       float64       `json:"benchmark_fp_rate"`
	BenchmarkAvgLatencyMS float64       `json:"benchmark_avg_latency_ms"`
	BenchmarkP95LatencyMS float64       `json:"benchmark_p95_latency_ms"`
	InstallStatus         InstallStatus `json:"install_status"`
	IsActive              bool          `json:"is_active"`
	DefaultAction         ThreatAction  `json:"default_action"`
	CriticalToolsJSON     string        `json:"critical_tools_json"`
	ParsedCriticalTools   []string      `json:"-"`
	NumLayers             int           `json:"num_layers"`
	NumKVHeads            int           `json:"num_kv_heads"`
	HeadDim               int           `json:"head_dim"`
	ContextWindow         int           `json:"context_window"`
	SourceURL             string        `json:"source_url"`
	OllamaSource          string        `json:"ollama_source"`
	DockerImage           string        `json:"docker_image"`
	EndpointURL           string        `json:"endpoint_url"`
	RuntimeType           string        `json:"runtime_type"`
	EntrypointScript      string        `json:"entrypoint_script,omitempty"`
	InstalledAt           *time.Time    `json:"installed_at,omitempty"`
	UpdatedAt             time.Time     `json:"updated_at"`
}

// GetCriticalTools returns the cached pre-parsed critical tools patterns or parses CriticalToolsJSON.
func (m *Model) GetCriticalTools() []string {
	if m == nil {
		return nil
	}
	if len(m.ParsedCriticalTools) > 0 {
		return m.ParsedCriticalTools
	}
	if m.CriticalToolsJSON != "" && m.CriticalToolsJSON != "[]" {
		var tools []string
		if err := json.Unmarshal([]byte(m.CriticalToolsJSON), &tools); err == nil {
			m.ParsedCriticalTools = tools
			return tools
		}
	}
	return nil
}

// DefaultModels returns the 6 official benchmarked security models seeded into the catalog.
func DefaultModels() []*Model {
	return []*Model{
		{
			ID:                    "laya-mlx",
			Name:                  "Laya MLX Guard",
			Family:                "mlx",
			Paradigm:              ModelParadigmDecisionModel,
			ParameterSize:         "Agent-Guard",
			RAMRequiredMB:         1800,
			DiskSizeMB:            1400,
			Description:           "Tailored agent security guard model with the highest threat detection accuracy (86.2%) in Farad AI Benchmark (FAB).",
			RecommendedFor:        "Workstations and production environments requiring maximum zero-day threat detection and deep semantic auditing.",
			BenchmarkAccuracy:     0.862,
			BenchmarkFPRate:       0.044,
			BenchmarkAvgLatencyMS: 24.2,
			BenchmarkP95LatencyMS: 38.5,
			InstallStatus:         InstallStatusNotInstalled,
			IsActive:              false,
			DefaultAction:         ThreatActionHITL,
			CriticalToolsJSON:     "[]",
			NumLayers:             32,
			NumKVHeads:            4,
			HeadDim:               128,
			ContextWindow:         2048,
			SourceURL:             "mlx-community/Laya-Guard-4bit",
			OllamaSource:          "hf.co/faradailab/guard-laya:latest",
			DockerImage:           "ghcr.io/faradailab/farad-ai-guard:laya",
			EntrypointScript:      "pkg/guards/scripts/laya_security_guard_mcp.py",
		},
		{
			ID:                    "qwen3guard",
			Name:                  "Qwen3Guard-0.6B",
			Family:                "mlx",
			Paradigm:              ModelParadigmGenerativeLLM,
			ParameterSize:         "0.6B",
			RAMRequiredMB:         1024,
			DiskSizeMB:            750,
			Description:           "Ultra-lightweight neural security model trained by Alibaba Cloud. Features the lowest false positive rate (3.3% FP) and fastest response time.",
			RecommendedFor:        "Developer laptops with 8GB-16GB RAM; lightweight, latency-sensitive protection for coding and development agents.",
			BenchmarkAccuracy:     0.796,
			BenchmarkFPRate:       0.033,
			BenchmarkAvgLatencyMS: 16.4,
			BenchmarkP95LatencyMS: 28.1,
			InstallStatus:         InstallStatusNotInstalled,
			IsActive:              false,
			DefaultAction:         ThreatActionHITL,
			CriticalToolsJSON:     "[]",
			NumLayers:             28,
			NumKVHeads:            2,
			HeadDim:               64,
			ContextWindow:         2048,
			SourceURL:             "Qwen/Qwen3Guard-Gen-0.6B",
			OllamaSource:          "hf.co/faradailab/guard-qwen3guard:latest",
			DockerImage:           "ghcr.io/faradailab/farad-ai-guard:qwen3guard",
			EntrypointScript:      "pkg/guards/scripts/qwen_security_guard_mcp.py",
		},
		{
			ID:                    "granite-guardian",
			Name:                  "IBM Granite Guardian 3.0-2B",
			Family:                "mlx",
			Paradigm:              ModelParadigmGenerativeLLM,
			ParameterSize:         "2.0B",
			RAMRequiredMB:         2500,
			DiskSizeMB:            1900,
			Description:           "Robust enterprise security guard based on IBM guardrail rulesets. Delivers balanced protection across OWASP Top 10 and systemic risks.",
			RecommendedFor:        "Strict enterprise compliance and data loss prevention (DLP) auditing.",
			BenchmarkAccuracy:     0.783,
			BenchmarkFPRate:       0.047,
			BenchmarkAvgLatencyMS: 34.8,
			BenchmarkP95LatencyMS: 52.4,
			InstallStatus:         InstallStatusNotInstalled,
			IsActive:              false,
			DefaultAction:         ThreatActionHITL,
			CriticalToolsJSON:     "[]",
			NumLayers:             40,
			NumKVHeads:            4,
			HeadDim:               64,
			ContextWindow:         2048,
			SourceURL:             "ibm-granite/granite-guardian-3.0-2b",
			OllamaSource:          "hf.co/faradailab/guard-granite:latest",
			DockerImage:           "ghcr.io/faradailab/farad-ai-guard:granite",
			EntrypointScript:      "pkg/guards/scripts/granite_security_guard_mcp.py",
		},
		{
			ID:                    "liquid-d1",
			Name:                  "Liquid AI d1-3B",
			Family:                "liquid",
			Paradigm:              ModelParadigmDecisionModel,
			ParameterSize:         "3.0B",
			RAMRequiredMB:         2350,
			DiskSizeMB:            1900,
			Description:           "Liquid AI non-autoregressive decision model. Hybrid architecture providing high accuracy and ultra-low latency in FAB benchmarks.",
			RecommendedFor:        "High-throughput agent intent verification and tool execution gating.",
			BenchmarkAccuracy:     0.841,
			BenchmarkFPRate:       0.038,
			BenchmarkAvgLatencyMS: 28.5,
			BenchmarkP95LatencyMS: 45.2,
			InstallStatus:         InstallStatusNotInstalled,
			IsActive:              false,
			DefaultAction:         ThreatActionHITL,
			CriticalToolsJSON:     "[]",
			NumLayers:             32,
			NumKVHeads:            4,
			HeadDim:               128,
			ContextWindow:         2048,
			SourceURL:             "LiquidAI/d1-3b",
			OllamaSource:          "hf.co/faradailab/guard-liquid-d1:latest",
			DockerImage:           "ghcr.io/faradailab/farad-ai-guard:liquid-d1",
			EntrypointScript:      "pkg/guards/scripts/liquid_security_guard_mcp.py",
		},
		{
			ID:                    "pplx-decider-flash",
			Name:                  "Perplexity Decider Flash v1.2",
			Family:                "perplexity",
			Paradigm:              ModelParadigmDecisionModel,
			ParameterSize:         "4.0B",
			RAMRequiredMB:         2050,
			DiskSizeMB:            1600,
			Description:           "Perplexity AI distilled routing and decision model (Qwen3.5-4B backbone). Q4_K_M quantized ultra-compact decision engine.",
			RecommendedFor:        "Complex multi-agent tool execution routing and policy compliance evaluation.",
			BenchmarkAccuracy:     0.855,
			BenchmarkFPRate:       0.036,
			BenchmarkAvgLatencyMS: 31.2,
			BenchmarkP95LatencyMS: 48.7,
			InstallStatus:         InstallStatusNotInstalled,
			IsActive:              false,
			DefaultAction:         ThreatActionHITL,
			CriticalToolsJSON:     "[]",
			NumLayers:             32,
			NumKVHeads:            4,
			HeadDim:               128,
			ContextWindow:         2048,
			SourceURL:             "perplexity/decider-flash-v1.2",
			OllamaSource:          "hf.co/faradailab/guard-pplx-decider:latest",
			DockerImage:           "ghcr.io/faradailab/farad-ai-guard:pplx-decider",
			EntrypointScript:      "pkg/guards/scripts/pplx_decider_guard_mcp.py",
		},
		{
			ID:                    "mica-v0.5",
			Name:                  "Mica v0.5-4B (Pure)",
			Family:                "qwen",
			Paradigm:              ModelParadigmDecisionModel,
			ParameterSize:         "4.0B",
			RAMRequiredMB:         2950,
			DiskSizeMB:            2450,
			Description:           "Qwen3.5-4B decision model quantized to Q4_K_M GGUF format by Mradermacher. Provides pure System 1 binary classification (/v1/systemone) and agent auditing.",
			RecommendedFor:        "Heavy agent governance, prompt injection defense, and remote code execution guardrails.",
			BenchmarkAccuracy:     0.871,
			BenchmarkFPRate:       0.032,
			BenchmarkAvgLatencyMS: 35.4,
			BenchmarkP95LatencyMS: 54.0,
			InstallStatus:         InstallStatusNotInstalled,
			IsActive:              false,
			DefaultAction:         ThreatActionHITL,
			CriticalToolsJSON:     "[]",
			NumLayers:             32,
			NumKVHeads:            4,
			HeadDim:               128,
			ContextWindow:         2048,
			SourceURL:             "mradermacher/Mica-v0.5-4B-GGUF",
			OllamaSource:          "hf.co/mradermacher/Mica-v0.5-4B-GGUF:Q4_K_M",
			DockerImage:           "ghcr.io/faradailab/farad-ai-guard:mica-v0.5",
			EntrypointScript:      "pkg/guards/scripts/mica_security_guard_mcp.py",
		},
	}
}
