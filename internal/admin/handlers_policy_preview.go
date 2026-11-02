package admin

import (
	"encoding/json"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

// handlePolicyRecommend analyzes attached protocols/tools and returns smart pack recommendations.
//   POST /admin/policy-packs/recommend
func (a *AdminServer) handlePolicyRecommend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST method is supported on /admin/policy-packs/recommend",
		})
		return
	}

	var req policy.RecommendationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_JSON",
			"message": "Failed to decode recommendation request: " + err.Error(),
		})
		return
	}

	recommender := policy.NewRecommender()
	recommendations := recommender.Recommend(req)
	if recommendations == nil {
		recommendations = make([]policy.Recommendation, 0)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"recommendations": recommendations,
	})
}

// handlePolicyPreview handles stateless dry-run policy compilation:
//   POST /admin/policies/preview
// Accepts an unpersisted AgentPolicyConfig JSON payload, compiles effective rules via Compiler,
// and returns the resolved compiled policy immediately without mutating database or filesystem state.
func (a *AdminServer) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only POST is supported on preview endpoint",
		})
		return
	}

	compiler := a.getPolicyCompiler()
	if compiler == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "POLICY_COMPILER_UNAVAILABLE",
			"message": "Policy compiler is not initialized",
		})
		return
	}

	var cfg policy.AgentPolicyConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_JSON",
			"message": "Failed to decode preview payload: " + err.Error(),
		})
		return
	}

	if cfg.AgentName == "" {
		cfg.AgentName = "preview-agent"
	}

	compiled, err := compiler.Compile(r.Context(), &cfg)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "COMPILATION_FAILED",
			"message": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"compiled": compiled,
	})
}

