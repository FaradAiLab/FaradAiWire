package admin

import (
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

// handlePolicyRecommend analyzes attached protocols/tools and returns smart pack recommendations.
//
//	POST /admin/policy-packs/recommend
func (a *AdminServer) handlePolicyRecommend(w http.ResponseWriter, r *http.Request) {
	var req policy.RecommendationRequest
	if err := decodeJSON(w, r, maxAdminBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode recommendation request: "+err.Error())
		return
	}

	recommender := policy.NewRecommender()
	recommendations := recommender.Recommend(req)
	if recommendations == nil {
		recommendations = make([]policy.Recommendation, 0)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"recommendations": recommendations,
	})
}

// handlePolicyPreview handles stateless dry-run policy compilation:
//
//	POST /admin/policies/preview
//
// Accepts an unpersisted AgentPolicyConfig JSON payload, compiles effective rules via Compiler,
// and returns the resolved compiled policy immediately without mutating database or filesystem state.
func (a *AdminServer) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	compiler := a.getPolicyCompiler()
	if compiler == nil {
		writeError(w, http.StatusServiceUnavailable, "POLICY_COMPILER_UNAVAILABLE", "Policy compiler is not initialized")
		return
	}

	var cfg policy.AgentPolicyConfig
	if err := decodeJSON(w, r, maxAdminBodyBytes, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode preview payload: "+err.Error())
		return
	}

	if cfg.AgentName == "" {
		cfg.AgentName = "preview-agent"
	}

	compiled, err := compiler.Compile(r.Context(), &cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, "COMPILATION_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"compiled": compiled,
	})
}
