package main

import (
	"strings"
	"testing"

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
