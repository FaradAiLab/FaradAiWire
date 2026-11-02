package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

// SetPolicyStore sets the DuckDB policy catalog store for the admin server.
func (a *AdminServer) SetPolicyStore(store policy.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policyStore = store
}

// SetPolicyCompiler sets the policy compiler for resolving and emitting agent dlp.json files.
func (a *AdminServer) SetPolicyCompiler(compiler *policy.Compiler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policyCompiler = compiler
}

func (a *AdminServer) getPolicyStore() policy.Store {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.policyStore
}

func (a *AdminServer) getPolicyCompiler() *policy.Compiler {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.policyCompiler
}

// handleDlpRules handles CRUD operations for individual DLP pattern rules:
//   GET    /admin/dlp/rules          -> List rules (optional ?category=...)
//   POST   /admin/dlp/rules          -> Create custom rule
//   GET    /admin/dlp/rules/{id}     -> Get single rule
//   PUT    /admin/dlp/rules/{id}     -> Update custom rule
//   DELETE /admin/dlp/rules/{id}     -> Delete custom rule
func (a *AdminServer) handleDlpRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	store := a.getPolicyStore()
	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "POLICY_STORE_UNAVAILABLE",
			"message": "Policy store is not initialized",
		})
		return
	}

	relPath := strings.TrimPrefix(r.URL.Path, "/admin/dlp/rules")
	relPath = strings.Trim(relPath, "/")

	// 1. Root collection: GET /admin/dlp/rules or POST /admin/dlp/rules
	if relPath == "" {
		switch r.Method {
		case http.MethodGet:
			category := r.URL.Query().Get("category")
			rules, err := store.ListRules(r.Context(), category)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "LIST_RULES_FAILED",
					"message": err.Error(),
				})
				return
			}
			if rules == nil {
				rules = make([]policy.DlpPatternRule, 0)
			}
			if r.URL.Query().Get("format") == "array" {
				json.NewEncoder(w).Encode(rules)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"rules": rules,
			})
			return

		case http.MethodPost:
			if a.cfg != nil && a.cfg.IsManaged() {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "FORBIDDEN_MANAGED_MODE",
					"message": "Policy editing is locked: Gateway is managed by organization.",
				})
				return
			}

			var rule policy.DlpPatternRule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "INVALID_JSON",
					"message": "Failed to decode rule payload: " + err.Error(),
				})
				return
			}

			if err := policy.ValidateRule(&rule); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "VALIDATION_FAILED",
					"message": err.Error(),
				})
				return
			}

			if err := store.CreateRule(r.Context(), &rule); err != nil {
				if errors.Is(err, policy.ErrRuleAlreadyExists) {
					w.WriteHeader(http.StatusConflict)
					json.NewEncoder(w).Encode(map[string]string{
						"error":   "RULE_EXISTS",
						"message": "A rule with ID " + rule.ID + " already exists",
					})
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "CREATE_RULE_FAILED",
					"message": err.Error(),
				})
				return
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"rule": rule,
			})
			return

		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "METHOD_NOT_ALLOWED",
				"message": "Only GET and POST methods are supported on /admin/dlp/rules",
			})
			return
		}
	}

	// 2. Single item operations: /admin/dlp/rules/{id}
	ruleID := relPath
	if err := policy.ValidateIdentifier(ruleID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_IDENTIFIER",
			"message": err.Error(),
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rule, err := store.GetRule(r.Context(), ruleID)
		if err != nil {
			if errors.Is(err, policy.ErrRuleNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "RULE_NOT_FOUND",
					"message": "Rule with ID " + ruleID + " was not found",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "GET_RULE_FAILED",
				"message": err.Error(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rule": rule,
		})
		return

	case http.MethodPut:
		if a.cfg != nil && a.cfg.IsManaged() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "FORBIDDEN_MANAGED_MODE",
				"message": "Policy editing is locked: Gateway is managed by organization.",
			})
			return
		}

		var rule policy.DlpPatternRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_JSON",
				"message": "Failed to decode rule payload: " + err.Error(),
			})
			return
		}
		rule.ID = ruleID

		if err := policy.ValidateRule(&rule); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "VALIDATION_FAILED",
				"message": err.Error(),
			})
			return
		}

		if err := store.UpdateRule(r.Context(), &rule); err != nil {
			if errors.Is(err, policy.ErrRuleNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "RULE_NOT_FOUND",
					"message": "Rule with ID " + ruleID + " was not found",
				})
				return
			}
			if errors.Is(err, policy.ErrImmutableBuiltin) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "IMMUTABLE_BUILTIN",
					"message": "Built-in rules cannot be modified",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "UPDATE_RULE_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"rule": rule,
		})
		return

	case http.MethodDelete:
		if a.cfg != nil && a.cfg.IsManaged() {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "FORBIDDEN_MANAGED_MODE",
				"message": "Policy editing is locked: Gateway is managed by organization.",
			})
			return
		}

		if err := store.DeleteRule(r.Context(), ruleID); err != nil {
			if errors.Is(err, policy.ErrRuleNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "RULE_NOT_FOUND",
					"message": "Rule with ID " + ruleID + " was not found",
				})
				return
			}
			if errors.Is(err, policy.ErrImmutableBuiltin) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "IMMUTABLE_BUILTIN",
					"message": "Built-in rules cannot be deleted",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "DELETE_RULE_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "deleted",
			"id":     ruleID,
		})
		return

	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET, PUT, and DELETE methods are supported on /admin/dlp/rules/{id}",
		})
		return
	}
}
