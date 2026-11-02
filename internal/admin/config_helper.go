package admin

// saveConfigAndReload triggers the runtime reload hook without rewriting config.yaml on disk (ADR-0053).
// This preserves human-authored comments, inline documentation, and prevents EROFS errors on
// read-only container and Kubernetes ConfigMap filesystem mounts.
func (a *AdminServer) saveConfigAndReload() error {
	a.mu.Lock()
	reloadFn := a.reloadFunc
	a.mu.Unlock()

	if reloadFn != nil {
		if err := reloadFn(); err != nil {
			return err
		}
	}

	return nil
}
