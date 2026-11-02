package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/FaradAiLab/FaradAiWire/internal/filter/audit"
)

// executeAudit audits a local directory or remote repository and renders results.
// If jsonOutput is true, serializes audit.AuditReport as formatted JSON.
// Returns exit code 0 for clean, 2 for security issues, 1 for execution/system errors.
func executeAudit(target string, jsonOutput bool, out io.Writer) int {
	var report *audit.AuditReport
	var err error

	if audit.IsRemoteTarget(target) {
		report, err = audit.AuditRemoteTarget(context.Background(), target)
	} else {
		report, err = audit.AuditDirectory(target)
	}

	if err != nil {
		if jsonOutput {
			errReport := map[string]interface{}{
				"target": target,
				"error":  err.Error(),
				"status": "ERROR",
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			_ = enc.Encode(errReport)
		} else {
			fmt.Fprintf(out, "Scanning skill directory: %s\n", target)
			fmt.Fprintf(out, "Error: Audit scan failed: %v\n", err)
		}
		return 1
	}

	if jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(out, `{"error": "failed to encode json: %v"}`+"\n", err)
			return 1
		}
		if len(report.Issues) > 0 {
			return 2
		}
		return 0
	}

	fmt.Fprintf(out, "Scanning skill directory: %s\n", target)

	// Output scanned files and language summary
	langBreakdown := report.FormatLanguageBreakdown()
	if report.ScannedFilesCount == 1 {
		fmt.Fprintf(out, "Scanned 1 file across %s.\n", langBreakdown)
	} else {
		fmt.Fprintf(out, "Scanned %d files across %s.\n", report.ScannedFilesCount, langBreakdown)
	}

	type categoryCheck struct {
		cat   audit.ThreatCategory
		label string
	}

	checks := []categoryCheck{
		{audit.CategoryShellExecution, "No malicious shell invocations found"},
		{audit.CategoryCredentialHarvesting, "No credential harvesting signatures detected"},
		{audit.CategoryDestructiveCommands, "No destructive system commands found"},
		{audit.CategoryNetworkBackdoor, "No unauthorized outbound network connections found"},
		{audit.CategoryDangerousEval, "No dangerous runtime eval/exec execution found"},
		{audit.CategoryPrivilegeEscalation, "No privilege escalation commands detected"},
		{audit.CategoryOpaqueBinary, "No opaque binary executables detected"},
	}

	if len(report.Issues) == 0 {
		for _, c := range checks {
			fmt.Fprintf(out, "[✓] %s\n", c.label)
		}
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Audit Result: PASSED (No threat signatures detected)")
		fmt.Fprintln(out, "Exit Code: 0")
		return 0
	}

	// If issues exist, render issues with line-level details
	for _, issue := range report.Issues {
		sev := strings.ToUpper(issue.Severity)
		fmt.Fprintf(out, "[ALERT: %s] %s in %s:%d\n", sev, issue.Reason, issue.FilePath, issue.LineNum)
		if issue.Code != "" {
			fmt.Fprintf(out, "    ↳ Matched: '%s'\n", issue.Code)
		}
	}

	fmt.Fprintln(out, "")
	issueWord := "vulnerabilities"
	if len(report.Issues) == 1 {
		issueWord = "vulnerability"
	}
	fmt.Fprintf(out, "Audit Result: FAILED (%d %s detected)\n", len(report.Issues), issueWord)
	fmt.Fprintln(out, "Exit Code: 2")
	return 2
}
