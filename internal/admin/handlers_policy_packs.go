package admin

import (
	"errors"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

func writePackStorageError(w http.ResponseWriter, packID string, err error, failCode, builtinMsg string) {
	if errors.Is(err, policy.ErrPackNotFound) {
		writeError(w, http.StatusNotFound, "PACK_NOT_FOUND", "Policy pack with ID "+packID+" was not found")
		return
	}
	if errors.Is(err, policy.ErrImmutableBuiltin) {
		writeError(w, http.StatusForbidden, "IMMUTABLE_BUILTIN", builtinMsg)
		return
	}
	writeError(w, http.StatusInternalServerError, failCode, err.Error())
}

// handleListPolicyPacks lists all configured DLP policy packs (GET /admin/policy-packs).
func (a *AdminServer) handleListPolicyPacks(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}

	packs, err := store.ListPacks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LIST_PACKS_FAILED", err.Error())
		return
	}
	if packs == nil {
		packs = make([]policy.PolicyPack, 0)
	}
	if r.URL.Query().Get("format") == "array" {
		writeJSON(w, http.StatusOK, packs)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"packs": packs})
}

// handleCreatePolicyPack creates a custom DLP policy pack (POST /admin/policy-packs).
func (a *AdminServer) handleCreatePolicyPack(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}

	var pack policy.PolicyPack
	if err := decodeJSON(w, r, maxAdminBodyBytes, &pack); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode policy pack payload: "+err.Error())
		return
	}
	if err := policy.ValidatePack(&pack); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	if err := store.CreatePack(r.Context(), &pack); err != nil {
		if errors.Is(err, policy.ErrPackAlreadyExists) {
			writeError(w, http.StatusConflict, "PACK_EXISTS", "A policy pack with ID "+pack.ID+" already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "CREATE_PACK_FAILED", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{"pack": pack})
}

// handleGetPolicyPack retrieves a single policy pack by ID (GET /admin/policy-packs/{id}).
func (a *AdminServer) handleGetPolicyPack(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}
	packID, ok := requireValidPolicyID(w, r)
	if !ok {
		return
	}

	pack, err := store.GetPack(r.Context(), packID)
	if err != nil {
		writePackStorageError(w, packID, err, "GET_PACK_FAILED", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pack": pack})
}

// handleUpdatePolicyPack updates a custom policy pack and propagates changes to agents (PUT /admin/policy-packs/{id}).
func (a *AdminServer) handleUpdatePolicyPack(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}
	packID, ok := requireValidPolicyID(w, r)
	if !ok {
		return
	}

	var pack policy.PolicyPack
	if err := decodeJSON(w, r, maxAdminBodyBytes, &pack); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to decode policy pack payload: "+err.Error())
		return
	}
	pack.ID = packID

	if err := policy.ValidatePack(&pack); err != nil {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	if err := store.UpdatePack(r.Context(), &pack); err != nil {
		writePackStorageError(w, packID, err, "UPDATE_PACK_FAILED", "Built-in policy packs cannot be modified")
		return
	}

	// Trigger live propagation across inheriting agents if compiler is available
	var recompiledAgents []string
	if compiler := a.getPolicyCompiler(); compiler != nil {
		if recompiled, propErr := compiler.PropagatePackUpdate(r.Context(), packID); propErr == nil {
			recompiledAgents = recompiled
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pack":              pack,
		"recompiled_agents": recompiledAgents,
	})
}

// handleDeletePolicyPack deletes a custom policy pack by ID (DELETE /admin/policy-packs/{id}).
func (a *AdminServer) handleDeletePolicyPack(w http.ResponseWriter, r *http.Request) {
	store := a.requirePolicyStore(w)
	if store == nil {
		return
	}
	packID, ok := requireValidPolicyID(w, r)
	if !ok {
		return
	}

	if err := store.DeletePack(r.Context(), packID); err != nil {
		writePackStorageError(w, packID, err, "DELETE_PACK_FAILED", "Built-in policy packs cannot be deleted")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "deleted",
		"id":     packID,
	})
}
