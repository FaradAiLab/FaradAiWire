package admin

import (
	"net/http"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/transport"
)

func newTestAdminServer(opts ...func(*AdminDependencies)) *AdminServer {
	var deps AdminDependencies
	for _, opt := range opts {
		if opt != nil {
			opt(&deps)
		}
	}
	return NewAdminServer(deps)
}

func withLoopbackProbeAllowed() func(*AdminDependencies) {
	return func(d *AdminDependencies) {
		var cfg *config.Config
		if d.Config != nil {
			cfg = d.Config.Clone()
		} else {
			cfg = &config.Config{}
		}
		cfg.Security.SSRFProtection.Enabled = new(bool)
		d.Config = cfg
		d.SafeHTTPClient = transport.NewSafeHTTPClient(transport.SafeTransportOptions{Enabled: false}, 5*time.Second)
	}
}

func withSafeHTTPClientOpt(c *http.Client) func(*AdminDependencies) {
	return func(d *AdminDependencies) {
		d.SafeHTTPClient = c
	}
}
