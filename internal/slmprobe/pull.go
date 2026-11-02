package slmprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var validModelNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/:]+$`)

// PullProgress represents a point-in-time progress update during an Ollama model pull.
type PullProgress struct {
	Status    string  `json:"status"`
	Digest    string  `json:"digest,omitempty"`
	Total     int64   `json:"total,omitempty"`
	Completed int64   `json:"completed,omitempty"`
	Percent   float64 `json:"percent,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Puller orchestrates streaming model pulls from an Ollama daemon.
type Puller struct {
	client *http.Client
}

// PullerOption configures a Puller instance.
type PullerOption func(*Puller)

// WithPullerHTTPClient configures a custom HTTP client for the puller.
func WithPullerHTTPClient(client *http.Client) PullerOption {
	return func(p *Puller) {
		if client != nil {
			p.client = client
		}
	}
}

// NewPuller constructs a Puller instance.
func NewPuller(opts ...PullerOption) *Puller {
	p := &Puller{
		client: &http.Client{
			Timeout: 0, // Streaming requests are controlled via Context
		},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// DefaultPuller is the package-level default instance.
var DefaultPuller = NewPuller()

// Pull streams the download of a model from Ollama, invoking onProgress for each update.
func Pull(ctx context.Context, ollamaURL, modelName string, onProgress func(PullProgress)) error {
	return DefaultPuller.Pull(ctx, ollamaURL, modelName, onProgress)
}

// Pull streams the download of a model from Ollama, invoking onProgress for each update.
func (p *Puller) Pull(ctx context.Context, ollamaURL, modelName string, onProgress func(PullProgress)) error {
	trimmedName := strings.TrimSpace(modelName)
	if trimmedName == "" || !validModelNameRegex.MatchString(trimmedName) || strings.Contains(trimmedName, "..") {
		return fmt.Errorf("invalid model name: %s", modelName)
	}

	parsedURL, err := url.Parse(strings.TrimSpace(ollamaURL))
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("invalid Ollama URL '%s': only http/https allowed", ollamaURL)
	}

	targetURL := strings.TrimRight(ollamaURL, "/")
	if !strings.HasSuffix(targetURL, "/api/pull") {
		targetURL += "/api/pull"
	}

	payload := map[string]interface{}{
		"name":   trimmedName,
		"stream": true,
	}

	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal pull request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBytes))
	if err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson, application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama pull request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(bodySnippet))
	}

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var event PullProgress
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}

		if event.Error != "" {
			return fmt.Errorf("ollama pull error: %s", event.Error)
		}

		if event.Total > 0 && event.Completed > 0 {
			event.Percent = float64(event.Completed) / float64(event.Total) * 100.0
		}

		if onProgress != nil {
			onProgress(event)
		}
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading pull stream: %w", err)
	}

	return nil
}
