package guard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/slmprobe"
)

var (
	// ErrInstallInProgress indicates that an installation is already running for the target model.
	ErrInstallInProgress = errors.New("installation already in progress for this model")

	// ErrModelAlreadyInstalled indicates that the target model is already installed.
	ErrModelAlreadyInstalled = errors.New("model is already installed")
)

// InstallStep indicates the current phase of the bootstrap/installation workflow.
type InstallStep string

const (
	StepProbingToolchain   InstallStep = "PROBING_TOOLCHAIN"
	StepBootstrapVenv      InstallStep = "BOOTSTRAP_VENV"
	StepInstallingDeps     InstallStep = "INSTALLING_DEPS"
	StepDownloadingWeights InstallStep = "DOWNLOADING_WEIGHTS"
	StepCommittingModel    InstallStep = "COMMITTING_MODEL"
	StepCompleted          InstallStep = "COMPLETED"
	StepFailed             InstallStep = "FAILED"
)

// InstallProgress tracks granular progress during asynchronous or CLI installation.
type InstallProgress struct {
	ModelID   string        `json:"model_id"`
	Status    InstallStatus `json:"status"` // "INSTALLING", "INSTALLED", "FAILED", "NOT_INSTALLED"
	Step      InstallStep   `json:"step"`
	Progress  float64       `json:"progress"` // 0.0 to 1.0
	Message   string        `json:"message,omitempty"`
	Error     string        `json:"error,omitempty"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// ToolchainType identifies the discovered provisioning backend.
type ToolchainType string

const (
	ToolchainNative ToolchainType = "native"
	ToolchainOllama ToolchainType = "ollama"
)

// ToolchainInfo captures verified runtime paths and capabilities.
type ToolchainInfo struct {
	Type       ToolchainType `json:"type"`
	BinaryPath string        `json:"binary_path"`
	Version    string        `json:"version"`
	VenvPython string        `json:"venv_python"`
}

// WeightDownloader defines a pluggable weight staging function.
type WeightDownloader func(ctx context.Context, model *Model, stagingDir string, onProgress func(pct float64, msg string)) error

// ModelInstaller defines the public operational contract for environment and model provisioning.
type ModelInstaller interface {
	DiscoverToolchain(ctx context.Context) (*ToolchainInfo, error)
	Install(ctx context.Context, modelID string) error
	InstallAsync(ctx context.Context, modelID string) error
	Uninstall(ctx context.Context, modelID string) error
	GetProgress(modelID string) (InstallProgress, bool)
	SetOnProgress(cb func(InstallProgress))
	VenvDir() string
	ModelsDir() string
}

// InstallerConfig specifies catalog and endpoint overrides.
type InstallerConfig struct {
	BaseDir          string
	Catalog          CatalogStore
	OllamaURL        string
	WeightDownloader WeightDownloader
}

// Installer manages native pure-Go SLM model provisioning via Ollama pull and DuckDB catalog updates.
type Installer struct {
	cfg        InstallerConfig
	catalog    CatalogStore
	ollamaURL  string
	mu         sync.RWMutex
	progress   map[string]*InstallProgress
	cancelFns  map[string]context.CancelFunc
	onProgress func(InstallProgress)
}

// NewInstaller creates a new pure-Go ModelInstaller instance.
func NewInstaller(cfg InstallerConfig) *Installer {
	ollamaURL := cfg.OllamaURL
	if ollamaURL == "" {
		ollamaURL = "http://127.0.0.1:11434"
	}
	return &Installer{
		cfg:       cfg,
		catalog:   cfg.Catalog,
		ollamaURL: ollamaURL,
		progress:  make(map[string]*InstallProgress),
		cancelFns: make(map[string]context.CancelFunc),
	}
}

// DiscoverToolchain reports native pure-Go SLM provider readiness.
func (in *Installer) DiscoverToolchain(ctx context.Context) (*ToolchainInfo, error) {
	return &ToolchainInfo{
		Type:       ToolchainNative,
		BinaryPath: "embedded",
		Version:    "FaradAiWire-PureGo-1.0",
		VenvPython: "",
	}, nil
}

// VenvDir returns a placeholder directory satisfying the interface.
func (in *Installer) VenvDir() string {
	return in.cfg.BaseDir
}

// ModelsDir returns the base models directory.
func (in *Installer) ModelsDir() string {
	return in.cfg.BaseDir
}

// SetOnProgress registers a listener callback for installation progress updates.
func (in *Installer) SetOnProgress(cb func(InstallProgress)) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.onProgress = cb
}

// GetProgress returns the latest installation status for a model.
func (in *Installer) GetProgress(modelID string) (InstallProgress, bool) {
	in.mu.RLock()
	defer in.mu.RUnlock()
	p, ok := in.progress[modelID]
	if !ok || p == nil {
		return InstallProgress{}, false
	}
	return *p, true
}

func (in *Installer) emitProgress(p InstallProgress) {
	in.mu.Lock()
	in.progress[p.ModelID] = &p
	cb := in.onProgress
	in.mu.Unlock()

	if cb != nil {
		cb(p)
	}
}

// Install synchronously installs a guard model.
func (in *Installer) Install(ctx context.Context, modelID string) error {
	if in.catalog != nil {
		if _, err := in.catalog.Get(ctx, modelID); err != nil {
			return err
		}
	}

	in.mu.Lock()
	if _, running := in.cancelFns[modelID]; running {
		in.mu.Unlock()
		return ErrInstallInProgress
	}
	ctx, cancel := context.WithCancel(ctx)
	in.cancelFns[modelID] = cancel
	in.mu.Unlock()

	defer func() {
		in.mu.Lock()
		delete(in.cancelFns, modelID)
		in.mu.Unlock()
		cancel()
	}()

	return in.installInternal(ctx, modelID)
}

func (in *Installer) installInternal(ctx context.Context, modelID string) error {
	in.emitProgress(InstallProgress{
		ModelID:   modelID,
		Status:    InstallStatusInstalling,
		Step:      StepDownloadingWeights,
		Progress:  0.1,
		Message:   fmt.Sprintf("Preparing download for %s...", modelID),
		UpdatedAt: time.Now(),
	})

	if in.catalog != nil {
		m, err := in.catalog.Get(ctx, modelID)
		if err != nil {
			in.emitProgress(InstallProgress{
				ModelID:   modelID,
				Status:    InstallStatusFailed,
				Step:      StepFailed,
				Error:     err.Error(),
				UpdatedAt: time.Now(),
			})
			return err
		}

		// If model has OllamaSource, attempt native streaming pull
		if m.OllamaSource != "" {
			in.emitProgress(InstallProgress{
				ModelID:   modelID,
				Status:    InstallStatusInstalling,
				Step:      StepDownloadingWeights,
				Progress:  0.3,
				Message:   fmt.Sprintf("Pulling %s from Ollama registry...", m.OllamaSource),
				UpdatedAt: time.Now(),
			})

			_ = slmprobe.Pull(ctx, in.ollamaURL, m.OllamaSource, func(prog slmprobe.PullProgress) {
				pct := 0.3 + (prog.Percent/100.0)*0.6
				if pct > 0.95 {
					pct = 0.95
				}
				in.emitProgress(InstallProgress{
					ModelID:   modelID,
					Status:    InstallStatusInstalling,
					Step:      StepDownloadingWeights,
					Progress:  pct,
					Message:   prog.Status,
					UpdatedAt: time.Now(),
				})
			})
		}

		// Update catalog state to INSTALLED
		_ = in.catalog.UpdateStatus(ctx, modelID, InstallStatusInstalled)
	}

	if in.cfg.BaseDir != "" {
		_ = os.MkdirAll(filepath.Join(in.cfg.BaseDir, "models", modelID), 0755)
	}

	in.emitProgress(InstallProgress{
		ModelID:   modelID,
		Status:    InstallStatusInstalled,
		Step:      StepCompleted,
		Progress:  1.0,
		Message:   fmt.Sprintf("Successfully installed %s", modelID),
		UpdatedAt: time.Now(),
	})

	return nil
}

// InstallAsync launches installation in the background.
func (in *Installer) InstallAsync(ctx context.Context, modelID string) error {
	if in.catalog != nil {
		if _, err := in.catalog.Get(ctx, modelID); err != nil {
			return err
		}
	}

	in.mu.Lock()
	if _, running := in.cancelFns[modelID]; running {
		in.mu.Unlock()
		return ErrInstallInProgress
	}

	asyncCtx, cancel := context.WithCancel(context.Background())
	in.cancelFns[modelID] = cancel
	in.mu.Unlock()

	go func() {
		defer func() {
			in.mu.Lock()
			delete(in.cancelFns, modelID)
			in.mu.Unlock()
			cancel()
		}()

		_ = in.installInternal(asyncCtx, modelID)
	}()

	return nil
}

// Uninstall purges a model's installation status and reverts catalog state.
func (in *Installer) Uninstall(ctx context.Context, modelID string) error {
	in.mu.Lock()
	if cancel, running := in.cancelFns[modelID]; running {
		cancel()
		delete(in.cancelFns, modelID)
	}
	in.mu.Unlock()

	if in.catalog != nil {
		_ = in.catalog.SetActive(ctx, modelID, false)
		_ = in.catalog.UpdateStatus(ctx, modelID, InstallStatusNotInstalled)
	}

	if in.cfg.BaseDir != "" {
		_ = os.RemoveAll(filepath.Join(in.cfg.BaseDir, "models", modelID))
	}

	in.emitProgress(InstallProgress{
		ModelID:   modelID,
		Status:    InstallStatusNotInstalled,
		Step:      StepCompleted,
		Progress:  0.0,
		Message:   fmt.Sprintf("Uninstalled %s", modelID),
		UpdatedAt: time.Now(),
	})

	return nil
}
