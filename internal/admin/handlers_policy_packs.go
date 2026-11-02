package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/policy"
)

func (a *AdminServer) handlePolicyPacks(w http.ResponseWriter, r *http.Request) {
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

	compiler := a.getPolicyCompiler()

	relPath := strings.TrimPrefix(r.URL.Path, "/admin/policy-packs")
	relPath = strings.Trim(relPath, "/")

	if relPath == "recommend" {
		a.handlePolicyRecommend(w, r)
		return
	}

	// 1. Root collection: GET /admin/policy-packs or POST /admin/policy-packs
	if relPath == "" {
		switch r.Method {
		case http.MethodGet:
			packs, err := store.ListPacks(r.Context())
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "LIST_PACKS_FAILED",
					"message": err.Error(),
				})
				return
			}
			if packs == nil {
				packs = make([]policy.PolicyPack, 0)
			}
			if r.URL.Query().Get("format") == "array" {
				json.NewEncoder(w).Encode(packs)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"packs": packs,
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

			var pack policy.PolicyPack
			if err := json.NewDecoder(r.Body).Decode(&pack); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "INVALID_JSON",
					"message": "Failed to decode policy pack payload: " + err.Error(),
				})
				return
			}

			if err := policy.ValidatePack(&pack); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "VALIDATION_FAILED",
					"message": err.Error(),
				})
				return
			}

			if err := store.CreatePack(r.Context(), &pack); err != nil {
				if errors.Is(err, policy.ErrPackAlreadyExists) {
					w.WriteHeader(http.StatusConflict)
					json.NewEncoder(w).Encode(map[string]string{
						"error":   "PACK_EXISTS",
						"message": "A policy pack with ID " + pack.ID + " already exists",
					})
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "CREATE_PACK_FAILED",
					"message": err.Error(),
				})
				return
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"pack": pack,
			})
			return

		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "METHOD_NOT_ALLOWED",
				"message": "Only GET and POST methods are supported on /admin/policy-packs",
			})
			return
		}
	}

	// 2. Single item operations: /admin/policy-packs/{id}
	packID := relPath
	if err := policy.ValidateIdentifier(packID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "INVALID_IDENTIFIER",
			"message": err.Error(),
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		pack, err := store.GetPack(r.Context(), packID)
		if err != nil {
			if errors.Is(err, policy.ErrPackNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "PACK_NOT_FOUND",
					"message": "Policy pack with ID " + packID + " was not found",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "GET_PACK_FAILED",
				"message": err.Error(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"pack": pack,
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

		var pack policy.PolicyPack
		if err := json.NewDecoder(r.Body).Decode(&pack); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_JSON",
				"message": "Failed to decode policy pack payload: " + err.Error(),
			})
			return
		}
		pack.ID = packID

		if err := policy.ValidatePack(&pack); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "VALIDATION_FAILED",
				"message": err.Error(),
			})
			return
		}

		if err := store.UpdatePack(r.Context(), &pack); err != nil {
			if errors.Is(err, policy.ErrPackNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "PACK_NOT_FOUND",
					"message": "Policy pack with ID " + packID + " was not found",
				})
				return
			}
			if errors.Is(err, policy.ErrImmutableBuiltin) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "IMMUTABLE_BUILTIN",
					"message": "Built-in policy packs cannot be modified",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "UPDATE_PACK_FAILED",
				"message": err.Error(),
			})
			return
		}

		// Trigger live propagation across inheriting agents if compiler is available
		var recompiledAgents []string
		if compiler != nil {
			recompiled, propErr := compiler.PropagatePackUpdate(r.Context(), packID)
			if propErr == nil {
				recompiledAgents = recompiled
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"pack":              pack,
			"recompiled_agents": recompiledAgents,
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

		if err := store.DeletePack(r.Context(), packID); err != nil {
			if errors.Is(err, policy.ErrPackNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "PACK_NOT_FOUND",
					"message": "Policy pack with ID " + packID + " was not found",
				})
				return
			}
			if errors.Is(err, policy.ErrImmutableBuiltin) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "IMMUTABLE_BUILTIN",
					"message": "Built-in policy packs cannot be deleted",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "DELETE_PACK_FAILED",
				"message": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "deleted",
			"id":     packID,
		})
		return

	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "METHOD_NOT_ALLOWED",
			"message": "Only GET, PUT, and DELETE methods are supported on /admin/policy-packs/{id}",
		})
		return
	}
}

