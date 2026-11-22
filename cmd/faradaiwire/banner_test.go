package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaradAiLab/FaradAiWire/internal/auth"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestPrintStartupBanner_Standby(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  "0.0.0.0",
		ListenPort:  19410,
		AdminHost:   "127.0.0.1",
		AdminPort:   19415,
	}
	cfg.Filters.DLP.Enabled = true
	cfg.Filters.LoopProtection.Enabled = true
	cfg.Filters.InjectionScanner.Enabled = true
	cfg.Filters.InjectionScanner.ClassifierURL = ""

	var buf strings.Builder
	printStartupBanner(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "FaradAiWire v") {
		t.Errorf("expected banner to contain FaradAiWire header")
	}
	if strings.Contains(out, "FaradAiWire vv") {
		t.Errorf("expected single 'v' prefix in banner header, got: %s", out)
	}
	if !strings.Contains(out, "http://0.0.0.0:19410") {
		t.Errorf("expected banner to contain ingress address http://0.0.0.0:19410, got: %s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:19415") {
		t.Errorf("expected banner to contain admin address http://127.0.0.1:19415, got: %s", out)
	}
	if !strings.Contains(out, "DLP & Secrets Redaction  : [ACTIVE]") {
		t.Errorf("expected DLP active tag")
	}
	if !strings.Contains(out, "AI Guard                 : [STANDBY - REGEX]") {
		t.Errorf("expected AI Guard standby tag")
	}
	if !strings.Contains(out, "💡 Hint:") {
		t.Errorf("expected hint line in standby mode")
	}
}

func TestPrintStartupBanner_Disabled(t *testing.T) {
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		ListenHost:  "127.0.0.1",
		ListenPort:  8090,
		AdminPort:   8095,
	}
	cfg.Filters.InjectionScanner.Enabled = false

	var buf strings.Builder
	printStartupBanner(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "AI Guard                 : [DISABLED]") {
		t.Errorf("expected AI Guard disabled tag")
	}
}

func TestIsInteractiveTerminal_InTests(t *testing.T) {
	// In go test, CI can be simulated or stdout is not a character device
	t.Setenv("CI", "true")
	if isInteractiveTerminal() {
		t.Errorf("expected isInteractiveTerminal() to be false when CI=true")
	}

	t.Setenv("CI", "")
	t.Setenv("FARADAI_WIRE_NO_BANNER", "true")
	if isInteractiveTerminal() {
		t.Errorf("expected isInteractiveTerminal() to be false when FARADAI_WIRE_NO_BANNER=true")
	}
}

func TestPrintStartupBanner_ZeroBleedTokenMasking(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempHome)

	ks, err := auth.NewFileKeyStore(filepath.Join(tempHome, "keys", "api_keys.json"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	rawKey, _, err := ks.GenerateKey("bootstrap-admin", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	allowStdio := false
	cfg := &config.Config{
		RuntimeMode: config.RuntimeModeStandalone,
		AllowStdio:  &allowStdio,
		ListenHost:  "0.0.0.0",
		ListenPort:  19410,
		AdminHost:   "0.0.0.0",
		AdminPort:   19415,
	}

	var buf strings.Builder
	printStartupBanner(cfg, &buf)
	out := buf.String()

	if strings.Contains(out, rawKey) {
		t.Fatalf("CRITICAL: startup banner leaked raw secret key into stdout logs:\n%s", out)
	}
	if !strings.Contains(out, auth.MaskTokenPrefix(rawKey)) {
		t.Errorf("expected masked token prefix %q in banner:\n%s", auth.MaskTokenPrefix(rawKey), out)
	}
	if !strings.Contains(out, "docker exec -it <container_name> faradaiwire token") {
		t.Errorf("expected containerized recovery CLI hint in banner:\n%s", out)
	}
	if !strings.Contains(out, "--port <host_port>") {
		t.Errorf("expected containerized port hint in banner:\n%s", out)
	}
}

func TestCLI_TokenCommand_RecoversBootstrapAdminKeyAndMagicLink(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("FARADAI_WIRE_HOME", tempHome)

	ks, err := auth.NewFileKeyStore(filepath.Join(tempHome, "keys", "api_keys.json"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	rawKey, _, err := ks.GenerateKey("bootstrap-admin", "Admin", "*")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"token"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("faradaiwire token exited %d (stderr=%s stdout=%s)", code, stderr.String(), stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, rawKey) {
		t.Fatalf("expected raw bootstrap key %q in token output:\n%s", rawKey, out)
	}
	if !strings.Contains(out, "/admin/dashboard?token="+rawKey) {
		t.Fatalf("expected Magic Link in token output:\n%s", out)
	}

	// Verify --json output
	stdout.Reset()
	stderr.Reset()
	code = runCLI([]string{"token", "--json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("faradaiwire token --json exited %d: %s", code, stderr.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal json token output: %v (%s)", err, stdout.String())
	}
	if payload["api_key"] != rawKey || !strings.Contains(payload["magic_link"], "?token="+rawKey) {
		t.Fatalf("unexpected json token payload: %+v", payload)
	}

	// Verify containerized port hint and --port override
	t.Setenv("FARADAI_WIRE_ALLOW_STDIO", "false")
	stdout.Reset()
	stderr.Reset()
	code = runCLI([]string{"token"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("faradaiwire token (containerized) exited %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "--port <host_port>") {
		t.Fatalf("expected containerized port hint in token output:\n%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCLI([]string{"token", "--port", "19425"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("faradaiwire token --port 19425 exited %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), ":19425/admin/dashboard?token="+rawKey) {
		t.Fatalf("expected overridden port in Magic Link:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "--port <host_port>") {
		t.Fatalf("did not expect port hint when --port override is provided:\n%s", stdout.String())
	}
}
