package admin

import "github.com/FaradAiLab/FaradAiWire/internal/config"

// cloneAndMutateConfig safely clones a.cfg when reloadConfigFunc is wired (or mutates a.cfg in place
// for standalone tests without a reload hook) and applies fn under a.mu.Lock().
func (a *AdminServer) cloneAndMutateConfig(fn func(*config.Config)) *config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg == nil {
		return nil
	}
	var nextCfg *config.Config
	if a.reloadConfigFunc != nil {
		nextCfg = a.cfg.Clone()
	} else {
		nextCfg = a.cfg
	}
	fn(nextCfg)
	return nextCfg
}

// applyConfigReload triggers the runtime pipeline reload hook without rewriting config.yaml on disk (ADR-0053).
// When reloadConfigFunc is wired (live Gateway), it swaps the pipeline atomically in memory using nextCfg
// instead of re-reading the unchanged config.yaml from disk.
func (a *AdminServer) applyConfigReload(nextCfg *config.Config) error {
	a.mu.RLock()
	reloadCfgFn := a.reloadConfigFunc
	reloadFn := a.reloadFunc
	a.mu.RUnlock()

	if reloadCfgFn != nil && nextCfg != nil {
		return reloadCfgFn(nextCfg)
	}
	if reloadFn != nil {
		return reloadFn()
	}
	return nil
}

// saveConfigAndReload preserves backward compatibility for callers triggering reload without a new config pointer.
func (a *AdminServer) saveConfigAndReload() error {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	return a.applyConfigReload(cfg)
}
