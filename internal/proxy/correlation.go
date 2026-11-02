package proxy

import (
	"github.com/FaradAiLab/FaradAiWire/internal/session"
)

// Re-export correlation types from session package for backward compatibility.
type CorrelationKey = session.CorrelationKey
type PendingRequest = session.PendingRequest
type CorrelationStore = session.CorrelationStore
type MemoryCorrelationStore = session.MemoryCorrelationStore

var NewCorrelationKey = session.NewCorrelationKey
var NewMemoryCorrelationStore = session.NewMemoryCorrelationStore
