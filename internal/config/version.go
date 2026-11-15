package config

import "strings"

// Version defines the current semantic version of FaradAiWire Core.
const Version = "v0.1.3"

// RuntimeVersion holds the active binary version, defaulting to Version and
// overridable at link time (-ldflags) or startup from cmd/faradaiwire.
var RuntimeVersion = Version

// GetVersion returns the normalized active version string with a leading "v".
func GetVersion() string {
	v := strings.TrimSpace(RuntimeVersion)
	if v == "" {
		v = Version
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}
