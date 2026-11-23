package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

func (a *AdminServer) getPolicyStore() policy.Store {
	return a.policyStore
}

func (a *AdminServer) getPolicyCompiler() *policy.Compiler {
	return a.policyCompiler
}

func (a *AdminServer) requirePolicyStore(w http.ResponseWriter) policy.Store {
	store := a.getPolicyStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "POLICY_STORE_UNAVAILABLE", "Policy store is not initialized")
		return nil
	}
	return store
}

func requireValidPolicyID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := strings.TrimSpace(r.PathValue("id"))
	if err := policy.ValidateIdentifier(id); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IDENTIFIER", err.Error())
		return "", false
	}
	return id, true
}

func writeRuleStorageError(w http.ResponseWriter, ruleID string, err error, failCode, builtinMsg string) {
	if errors.Is(err, policy.ErrRuleNotFound) {
		writeError(w, http.StatusNotFound, "RULE_NOT_FOUND", "Rule with ID "+ruleID+" was not found")
		return
	}
	if errors.Is(err, policy.ErrImmutableBuiltin) {
		writeError(w, http.StatusForbidden, "IMMUTABLE_BUILTIN", builtinMsg)
		return
	}
	writeError(w, http.StatusInternalServerError, failCode, err.Error())
}

// handleListDlpRules lists all DLP pattern rules with optional ?category= filtering (GET /admin/dlp/rules).
func (a *AdminServer) handleListDlpRules(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}

	rules, err := store.ListRules(r.Context(), r.URL.Query().Get("category"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LIST_RULES_FAILED", err.Error())
		return
	}
	if rules == nil {
		rules = make([]policy.DlpPatternRule, 0)
	}
	if r.URL.Query().Get("format") == "array" {
		writeJSON(w, http.StatusOK, rules)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rules": rules})
}

// handleCreateDlpRule creates a custom DLP pattern rule (POST /admin/dlp/rules).
func (a *AdminServer) handleCreateDlpRule(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}

	var rule policy.DlpPatternRule
	if err := decodeJSON(w, r, maxAdminBodyBytes, &rule); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode rule payload: "+err.Error())
		return
	}
	if err := policy.ValidateRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	if err := store.CreateRule(r.Context(), &rule); err != nil {
		if errors.Is(err, policy.ErrRuleAlreadyExists) {
			writeError(w, http.StatusConflict, "RULE_EXISTS", "A rule with ID "+rule.ID+" already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "CREATE_RULE_FAILED", err.Error())
		return
	}

	a.logSecurityAudit(r, "dlp_rule_mutated", "create", "dlp_rule", rule.ID, "allowed", "DLP rule created", map[string]any{
		"category":       rule.Category,
		"default_action": rule.DefaultAction,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{"rule": rule})
}

// handleGetDlpRule fetches a single DLP pattern rule by ID (GET /admin/dlp/rules/{id}).
func (a *AdminServer) handleGetDlpRule(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}
	ruleID, ok := requireValidPolicyID(w, r)
	if !ok {
		return
	}

	rule, err := store.GetRule(r.Context(), ruleID)
	if err != nil {
		writeRuleStorageError(w, ruleID, err, "GET_RULE_FAILED", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"rule": rule})
}

// handleUpdateDlpRule updates a custom DLP pattern rule (PUT /admin/dlp/rules/{id}).
func (a *AdminServer) handleUpdateDlpRule(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}
	ruleID, ok := requireValidPolicyID(w, r)
	if !ok {
		return
	}

	var rule policy.DlpPatternRule
	if err := decodeJSON(w, r, maxAdminBodyBytes, &rule); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode rule payload: "+err.Error())
		return
	}
	rule.ID = ruleID

	if err := policy.ValidateRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	if err := store.UpdateRule(r.Context(), &rule); err != nil {
		writeRuleStorageError(w, ruleID, err, "UPDATE_RULE_FAILED", "Built-in rules cannot be modified")
		return
	}

	a.logSecurityAudit(r, "dlp_rule_mutated", "update", "dlp_rule", ruleID, "allowed", "DLP rule updated", map[string]any{
		"category":       rule.Category,
		"default_action": rule.DefaultAction,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{"rule": rule})
}

// handleDeleteDlpRule deletes a custom DLP pattern rule (DELETE /admin/dlp/rules/{id}).
func (a *AdminServer) handleDeleteDlpRule(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}
	ruleID, ok := requireValidPolicyID(w, r)
	if !ok {
		return
	}

	if err := store.DeleteRule(r.Context(), ruleID); err != nil {
		writeRuleStorageError(w, ruleID, err, "DELETE_RULE_FAILED", "Built-in rules cannot be deleted")
		return
	}

	a.logSecurityAudit(r, "dlp_rule_mutated", "delete", "dlp_rule", ruleID, "allowed", "DLP rule deleted", nil)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "deleted",
		"id":     ruleID,
	})
}
