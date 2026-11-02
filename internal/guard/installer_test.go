package guard

import (
	"context"
	"errors"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

func TestInstaller_DiscoverToolchain(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()
	_ = cat.Seed(context.Background())

	tmpDir := t.TempDir()
	installer := NewInstaller(InstallerConfig{
		BaseDir: tmpDir,
		Catalog: cat,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tc, err := installer.DiscoverToolchain(ctx)
	if err != nil {
		t.Fatalf("discover toolchain failed: %v", err)
	}

	if tc.Type != ToolchainNative {
		t.Errorf("unexpected toolchain type: %s", tc.Type)
	}
}

func TestInstaller_Install_And_Uninstall(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()
	ctx := context.Background()
	_ = cat.Seed(ctx)

	installer := NewInstaller(InstallerConfig{
		Catalog: cat,
	})

	modelID := "laya-mlx"

	// 1. Install
	if err := installer.Install(ctx, modelID); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	prog, exists := installer.GetProgress(modelID)
	if !exists {
		t.Fatalf("expected progress to exist for %s", modelID)
	}
	if prog.Status != InstallStatusInstalled || prog.Progress != 1.0 {
		t.Errorf("unexpected progress after install: %+v", prog)
	}

	m, err := cat.Get(ctx, modelID)
	if err != nil {
		t.Fatalf("catalog get failed: %v", err)
	}
	if m.InstallStatus != InstallStatusInstalled {
		t.Errorf("expected catalog InstallStatus=INSTALLED, got %s", m.InstallStatus)
	}

	// 2. Uninstall
	if err := installer.Uninstall(ctx, modelID); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	progAfter, _ := installer.GetProgress(modelID)
	if progAfter.Status != InstallStatusNotInstalled {
		t.Errorf("expected status NOT_INSTALLED after uninstall, got %s", progAfter.Status)
	}

	mAfter, _ := cat.Get(ctx, modelID)
	if mAfter.InstallStatus != InstallStatusNotInstalled {
		t.Errorf("expected catalog InstallStatus=NOT_INSTALLED, got %s", mAfter.InstallStatus)
	}
}

func TestInstaller_InstallAsync(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()
	ctx := context.Background()
	_ = cat.Seed(ctx)

	installer := NewInstaller(InstallerConfig{
		Catalog: cat,
	})

	var eventCount int
	installer.SetOnProgress(func(p InstallProgress) {
		eventCount++
	})

	modelID := "laya-mlx"
	if err := installer.InstallAsync(ctx, modelID); err != nil {
		t.Fatalf("InstallAsync failed: %v", err)
	}

	// Wait up to 3 seconds for async installation to complete
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p, ok := installer.GetProgress(modelID)
		if ok && p.Status == InstallStatusInstalled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	p, ok := installer.GetProgress(modelID)
	if !ok || p.Status != InstallStatusInstalled {
		t.Fatalf("expected async install to succeed, got: %+v", p)
	}
	if eventCount == 0 {
		t.Errorf("expected progress events to be emitted")
	}
}

func TestInstaller_DuplicateInstall_Conflict(t *testing.T) {
	cat, db := setupTestCatalog(t)
	defer db.Close()
	ctx := context.Background()
	_ = cat.Seed(ctx)

	installer := NewInstaller(InstallerConfig{
		Catalog: cat,
	})

	modelID := "granite-guardian"
	installer.cancelFns[modelID] = func() {} // simulate in-flight installation

	err := installer.Install(ctx, modelID)
	if !errors.Is(err, ErrInstallInProgress) {
		t.Fatalf("expected ErrInstallInProgress, got: %v", err)
	}

	errAsync := installer.InstallAsync(ctx, modelID)
	if !errors.Is(errAsync, ErrInstallInProgress) {
		t.Fatalf("expected ErrInstallInProgress for async, got: %v", errAsync)
	}
}
