package config

import (
	"log/slog"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ConfigWatcher monitors configuration file changes using fsnotify.
type ConfigWatcher struct {
	provider   *YAMLConfigProvider
	watcher    *fsnotify.Watcher
	mu         sync.Mutex
	lastReload time.Time
}

// NewConfigWatcher initializes a watcher for the config file.
func NewConfigWatcher(provider *YAMLConfigProvider) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &ConfigWatcher{
		provider: provider,
		watcher:  watcher,
	}, nil
}

// Watch starts listening for filesystem events in a background goroutine and invokes onChange when a reload happens.
func (w *ConfigWatcher) Watch(onChange func(*Config)) error {
	// Add config file to watch list
	if err := w.watcher.Add(w.provider.filePath); err != nil {
		w.watcher.Close()
		return err
	}

	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				}
				// Watch for modifications or creations
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					w.mu.Lock()
					// Debounce multiple rapid events from editors
					if time.Since(w.lastReload) < 500*time.Millisecond {
						w.mu.Unlock()
						continue
					}
					w.lastReload = time.Now()
					w.mu.Unlock()

					slog.Info("Configuration change detected on filesystem", slog.String("file", event.Name))
					cfg, err := w.provider.Load()
					if err != nil {
						slog.Warn("Error loading updated configuration (retaining active config)", slog.String("error", err.Error()))
						continue
					}

					// Invoke reload callback
					onChange(cfg)
				}
			case err, ok := <-w.watcher.Errors:
				if !ok {
					return
				}
				slog.Error("Filesystem watcher error", slog.String("error", err.Error()))
			}
		}
	}()

	return nil
}

// Close stops the fsnotify watcher.
func (w *ConfigWatcher) Close() error {
	return w.watcher.Close()
}
