package admin

import "github.com/FaradAiLab/FaradAiWire/internal/config"

// cloneAndMutateConfig clones the active atomic Config and applies fn to the clone so
// failed reload transitions never leave partial mutations in runtime state.
func (a *AdminServer) cloneAndMutateConfig(fn func(*config.Config)) *config.Config {
	cfg := a.Config()
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
	if a.reloadConfigFunc != nil && nextCfg != nil {
		return a.reloadConfigFunc(nextCfg)
	}
	if a.reloadFunc != nil {
		if err := a.reloadFunc(); err != nil {
			return err
		}
	}
	if nextCfg != nil {
		a.SetConfig(nextCfg)
	}
	return nil
}
