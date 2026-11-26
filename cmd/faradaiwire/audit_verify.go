package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

func executeAuditCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printAuditUsage(stderr)
		return 1
	}
	if isHelpArg(args[0]) {
		printAuditUsage(stdout)
		return 0
	}

	switch args[0] {
	case "verify":
		return executeAuditVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown audit subcommand: %s\n\n", args[0])
		printAuditUsage(stderr)
		return 1
	}
}

func executeAuditVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && isHelpArg(args[0]) {
		printAuditUsage(stdout)
		return 0
	}

	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfgPath string
	var dbPath string
	var jsonlPath string
	var jsonOutput bool
	fs.StringVar(&cfgPath, "config", "", "Path to YAML configuration file")
	fs.StringVar(&dbPath, "db", "", "Path to telemetry DuckDB file")
	fs.StringVar(&jsonlPath, "jsonl", "", "Path to primary audit JSONL file")
	fs.BoolVar(&jsonOutput, "json", false, "Output structured JSON report")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// Load defaults from config only for flags not explicitly overridden on CLI
	explicitDB := false
	explicitJSONL := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "db":
			explicitDB = true
		case "jsonl":
			explicitJSONL = true
		}
	})

	if (!explicitDB && !explicitJSONL) || cfgPath != "" {
		prov := config.NewYAMLConfigProvider(cfgPath)
		if cfg, err := prov.Load(); err == nil && cfg != nil {
			if !explicitDB && cfg.IsTelemetryEnabled() {
				dbPath = cfg.GetTelemetryDBPath()
			}
			if !explicitJSONL && cfg.AuditLog.Enabled {
				jsonlPath = cfg.GetAuditLogPath()
			}
		}
	}

	if dbPath == "" && jsonlPath == "" {
		fmt.Fprintln(stderr, "Error: specify --db and/or --jsonl, or configure telemetry/audit_log in config.yaml")
		return 1
	}

	hmacKey := duckdb.ResolveAuditHMACKey()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var dbReport *duckdb.IntegrityReport
	var jsonlReport *logger.JSONLVerifyReport
	overallValid := true

	if dbPath != "" {
		rep, err := duckdb.VerifyDuckDBFile(ctx, dbPath, hmacKey)
		if err != nil {
			if errors.Is(err, duckdb.ErrDatabaseLocked) {
				msg := fmt.Sprintf("DuckDB database %q is locked by a running FaradAiWire daemon. Query GET http://127.0.0.1:19415/admin/audit/verify for live in-process verification or pass --jsonl.", dbPath)
				if jsonOutput {
					enc := json.NewEncoder(stdout)
					enc.SetIndent("", "  ")
					_ = enc.Encode(map[string]any{
						"valid": false,
						"error": "database_locked",
						"hint":  msg,
					})
				} else {
					fmt.Fprintln(stderr, "Error:", msg)
				}
				return 2
			}
			if !os.IsNotExist(err) || explicitDB {
				fmt.Fprintf(stderr, "Error verifying DuckDB %q: %v\n", dbPath, err)
				return 1
			}
		} else {
			dbReport = rep
			if !rep.Valid {
				overallValid = false
			}
		}
	}

	if jsonlPath != "" {
		rep, err := logger.VerifyAuditJSONL(jsonlPath, hmacKey)
		if err != nil {
			fmt.Fprintf(stderr, "Error verifying JSONL %q: %v\n", jsonlPath, err)
			return 1
		}
		jsonlReport = rep
		if !rep.Valid {
			overallValid = false
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"valid":  overallValid,
			"duckdb": dbReport,
			"jsonl":  jsonlReport,
		})
	} else {
		printHumanVerifyReport(stdout, overallValid, dbPath, jsonlPath, dbReport, jsonlReport)
	}

	if !overallValid {
		return 1
	}
	return 0
}

func printHumanVerifyReport(
	out io.Writer,
	overallValid bool,
	dbPath, jsonlPath string,
	dbRep *duckdb.IntegrityReport,
	jsonlRep *logger.JSONLVerifyReport,
) {
	status := "PASSED"
	if !overallValid {
		status = "FAILED (TAMPERING DETECTED)"
	}
	fmt.Fprintf(out, "Audit Integrity Verification: %s\n", status)
	if dbRep != nil {
		fmt.Fprintf(out, "  DuckDB (%s): valid=%v hmac=%v\n", dbPath, dbRep.Valid, dbRep.HMACEnabled)
		fmt.Fprintf(out, "    tool_audit_logs:      checked=%d v2=%d v1=%d tampered=%d\n",
			dbRep.ToolAuditLogs.Checked, dbRep.ToolAuditLogs.V2Verified, dbRep.ToolAuditLogs.LegacyV1, len(dbRep.ToolAuditLogs.TamperedIDs))
		fmt.Fprintf(out, "    tool_audit_responses: checked=%d v2=%d v1=%d tampered=%d\n",
			dbRep.ToolAuditResponses.Checked, dbRep.ToolAuditResponses.V2Verified, dbRep.ToolAuditResponses.LegacyV1, len(dbRep.ToolAuditResponses.TamperedIDs))
		fmt.Fprintf(out, "    security_audit_logs:  checked=%d v2=%d v1=%d tampered=%d\n",
			dbRep.SecurityAuditLogs.Checked, dbRep.SecurityAuditLogs.V2Verified, dbRep.SecurityAuditLogs.LegacyV1, len(dbRep.SecurityAuditLogs.TamperedIDs))
	}
	if jsonlRep != nil {
		fmt.Fprintf(out, "  JSONL (%s): valid=%v hmac=%v segments=%d entries=%d broken=%d\n",
			jsonlPath, jsonlRep.Valid, jsonlRep.HMACEnabled, jsonlRep.SegmentsChecked, jsonlRep.EntriesChecked, len(jsonlRep.BrokenSegments))
	}
}
