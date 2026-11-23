package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/logger"
	"github.com/FaradAiLab/FaradAiWire/internal/telemetry/duckdb"
)

func TestHelperHoldDuckDBLock(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_LOCK") != "1" {
		return
	}
	dbPath := os.Getenv("GO_LOCK_DB_PATH")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper open: %v\n", err)
		os.Exit(2)
	}
	defer db.Close()
	if _, err := db.Exec(`SELECT 1`); err != nil {
		fmt.Fprintf(os.Stderr, "helper exec: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("LOCKED")
	// Keep exclusive lock held until parent closes stdin
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

func TestCLI_AuditVerify_OfflineAndTamperAndLockedDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wire.duckdb")
	jsonlPath := filepath.Join(dir, "audit.jsonl")

	eng, err := duckdb.New(duckdb.Config{DBPath: dbPath, BufferSize: 50, BatchFlushMs: 10})
	if err != nil {
		t.Fatalf("duckdb.New: %v", err)
	}
	fl, err := logger.NewFileAuditLogger(jsonlPath)
	if err != nil {
		t.Fatalf("NewFileAuditLogger: %v", err)
	}
	ev := &filter.AuditEvent{
		ID:        "cli-verify-1",
		Timestamp: time.Now().UTC(),
		AgentName: "alpha",
		ToolName:  "read",
		Decision:  filter.DecisionAllowed,
	}
	eng.LogEvent(ev)
	fl.LogEvent(ev)
	_ = eng.Flush(context.Background())
	_ = fl.Close()
	_ = eng.Close()

	// 1. Hold OS-level DuckDB lock from a separate child process to verify locked DB handling
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldDuckDBLock$")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_LOCK=1", "GO_LOCK_DB_PATH="+dbPath)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start lock helper: %v", err)
	}
	readyCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdoutPipe).ReadString('\n')
		readyCh <- strings.TrimSpace(line)
	}()
	select {
	case msg := <-readyCh:
		if msg != "LOCKED" {
			_ = cmd.Process.Kill()
			t.Fatalf("unexpected lock helper output: %q", msg)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timed out waiting for DuckDB lock helper")
	}

	var out, errBuf bytes.Buffer
	code := runCLI([]string{"audit", "verify", "--db", dbPath, "--jsonl", jsonlPath}, strings.NewReader(""), &out, &errBuf)
	if code != 2 {
		_ = stdinPipe.Close()
		_ = cmd.Wait()
		t.Fatalf("expected exit 2 when DuckDB is locked, got %d (stdout=%s stderr=%s)", code, out.String(), errBuf.String())
	}
	combined := out.String() + errBuf.String()
	if !strings.Contains(combined, "/admin/audit/verify") || !strings.Contains(combined, "locked") {
		_ = stdinPipe.Close()
		_ = cmd.Wait()
		t.Fatalf("expected actionable locked DB guidance, got: %s", combined)
	}

	// 2. JSONL-only verification succeeds even while DB is locked by another process
	out.Reset()
	errBuf.Reset()
	code = runCLI([]string{"audit", "verify", "--jsonl", jsonlPath, "--json"}, strings.NewReader(""), &out, &errBuf)
	if code != 0 {
		_ = stdinPipe.Close()
		_ = cmd.Wait()
		t.Fatalf("audit verify --jsonl --json failed (%d): stdout=%s stderr=%s", code, out.String(), errBuf.String())
	}

	_ = stdinPipe.Close()
	_ = cmd.Wait()

	// 3. Clean unlocked DB + JSONL passes with exit 0
	out.Reset()
	errBuf.Reset()
	code = runCLI([]string{"audit", "verify", "--db", dbPath, "--jsonl", jsonlPath, "--json"}, strings.NewReader(""), &out, &errBuf)
	if code != 0 {
		t.Fatalf("audit verify clean failed (%d): stdout=%s stderr=%s", code, out.String(), errBuf.String())
	}
	var rep struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || !rep.Valid {
		t.Fatalf("expected valid=true JSON report, got err=%v out=%s", err, out.String())
	}

	// 4. Tamper JSONL -> audit verify returns non-zero exit code 1
	raw, _ := os.ReadFile(jsonlPath)
	_ = os.WriteFile(jsonlPath, []byte(strings.Replace(string(raw), `"ALLOWED"`, `"BLOCKED"`, 1)), 0600)
	out.Reset()
	errBuf.Reset()
	code = runCLI([]string{"audit", "verify", "--db", dbPath, "--jsonl", jsonlPath}, strings.NewReader(""), &out, &errBuf)
	if code != 1 {
		t.Fatalf("expected exit 1 on tampered JSONL, got %d (stdout=%s)", code, out.String())
	}
}
