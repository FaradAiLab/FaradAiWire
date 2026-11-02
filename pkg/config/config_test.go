package config_test

import (
	"testing"

	"github.com/FaradAiLab/FaradAiWire/pkg/config"
)

func TestConfigPublicAPI(t *testing.T) {
	if config.Version == "" {
		t.Errorf("expected Version to be non-empty")
	}
	if config.RuntimeModeStandalone != "STANDALONE" {
		t.Errorf("expected RuntimeModeStandalone 'STANDALONE', got %s", config.RuntimeModeStandalone)
	}
	if config.RuntimeModeManaged != "MANAGED" {
		t.Errorf("expected RuntimeModeManaged 'MANAGED', got %s", config.RuntimeModeManaged)
	}

	dir := config.DefaultFaradAiWireDir()
	if dir == "" {
		t.Errorf("expected DefaultFaradAiWireDir to return a path")
	}

	prov := config.NewYAMLConfigProvider("test.yaml")
	if prov == nil {
		t.Fatalf("expected NewYAMLConfigProvider to return non-nil")
	}
}
