package admin

import (
	"context"
	"net/http"

	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

// TelemetryIntegrityVerifier runs in-process cryptographic audit integrity checks across DuckDB tables.
type TelemetryIntegrityVerifier interface {
	VerifyIntegrity(ctx context.Context, hmacKey []byte) (*duckdb.IntegrityReport, error)
}

func (a *AdminServer) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	hmacKey := duckdb.ResolveAuditHMACKey()
	overallValid := true

	var dbReport *duckdb.IntegrityReport
	if verifier, ok := a.telemetryEngine.(TelemetryIntegrityVerifier); ok && verifier != nil {
		rep, err := verifier.VerifyIntegrity(r.Context(), hmacKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "VERIFY_DUCKDB_FAILED", "Failed to verify DuckDB audit integrity: "+err.Error())
			return
		}
		dbReport = rep
		if !rep.Valid {
			overallValid = false
		}
	}

	var jsonlReport *logger.JSONLVerifyReport
	if cfg := a.Config(); cfg != nil && cfg.AuditLog.Enabled && cfg.AuditLog.Path != "" {
		rep, err := logger.VerifyAuditJSONL(cfg.AuditLog.Path, hmacKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "VERIFY_JSONL_FAILED", "Failed to verify JSONL audit integrity: "+err.Error())
			return
		}
		jsonlReport = rep
		if !rep.Valid {
			overallValid = false
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":  overallValid,
		"duckdb": dbReport,
		"jsonl":  jsonlReport,
	})
}
