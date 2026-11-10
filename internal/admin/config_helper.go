package admin

import "github.com/FaradAiLab/FaradAiWire/internal/config"

// cloneAndMutateConfig always clones a.cfg under a.mu.RLock() and applies fn to the clone so
// failed reload transitions never leave partial mutations in runtime state.
func (a *AdminServer) cloneAndMutateConfig(fn func(*config.Config)) *config.Config {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if cfg == nil {
		return nil
	}
	nextCfg := cfg.Clone()
	fn(nextCfg)
	return nextCfg
}

// applyConfigReload triggers the runtime pipeline reload hook without rewriting config.yaml on disk (ADR-0053).
// When reloadConfigFunc is wired (live Gateway), it swaps the pipeline atomically in memory using nextCfg.
// Otherwise it invokes reloadFunc (if set) and commits nextCfg onto AdminServer on success.
func (a *AdminServer) applyConfigReload(nextCfg *config.Config) error {
	a.mu.RLock()
	reloadCfgFn := a.reloadConfigFunc
	reloadFn := a.reloadFunc
	a.mu.RUnlock()

	if reloadCfgFn != nil && nextCfg != nil {
		return reloadCfgFn(nextCfg)
	}
	if reloadFn != nil {
		if err := reloadFn(); err != nil {
			return err
		}
	}
	if nextCfg != nil {
		a.SetConfig(nextCfg)
	}
	return nil
}
