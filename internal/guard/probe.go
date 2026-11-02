package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProbeResult represents the outcome of probing an external inference provider endpoint.
type ProbeResult struct {
	Alive         bool     `json:"alive"`
	LatencyMS     float64  `json:"latency_ms"`
	ModelsFound   []string `json:"models_found"`
	ModelMatched  bool     `json:"model_matched"`
	DetectedModel string   `json:"detected_model,omitempty"`
	Message       string   `json:"message"`
}

// modelsProbeResponse parses both OpenAI (/v1/models) and Ollama (/api/tags) schemas.
type modelsProbeResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Models []struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	} `json:"models"`
}

// parseModelsFromJSON extracts model identifiers from both OpenAI (/v1/models) and Ollama (/api/tags) schemas.
func parseModelsFromJSON(data []byte) []string {
	var resp modelsProbeResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}

	var results []string
	for _, item := range resp.Data {
		if item.ID != "" {
			results = append(results, item.ID)
		}
	}
	for _, item := range resp.Models {
		if item.Name != "" {
			results = append(results, item.Name)
		} else if item.Model != "" {
			results = append(results, item.Model)
		}
	}
	return results
}

// ProbeAndVerify probes an external inference endpoint, tests reachability within 400ms SLA,
// and queries available models to verify whether the target guard model is loaded.
func ProbeAndVerify(ctx context.Context, targetURL string, runtimeType string, expectedModel string, customClient ...*http.Client) (*ProbeResult, error) {
	start := time.Now()
	cleanURL := strings.TrimRight(targetURL, "/")
	if cleanURL == "" {
		return nil, errors.New("empty target endpoint URL")
	}

	parsedURL, err := url.Parse(cleanURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL scheme %q: only http and https are permitted", cleanURL)
	}

	var client *http.Client
	if len(customClient) > 0 && customClient[0] != nil {
		client = customClient[0]
	} else {
		client = &http.Client{
			Timeout: 400 * time.Millisecond,
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()

	// Determine probe endpoints based on runtimeType
	var probePaths []string
	if runtimeType == "ollama" {
		probePaths = []string{"/api/tags", "/v1/models"}
	} else {
		probePaths = []string{"/v1/models", "/api/tags"}
	}

	var lastErr error
	var modelsFound []string
	var succeeded bool

	for _, path := range probePaths {
		reqURL := cleanURL + path
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, reqURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if readErr != nil {
				lastErr = readErr
			} else {
				lastErr = fmt.Errorf("probe to %s returned HTTP %d", path, resp.StatusCode)
			}
			continue
		}

		succeeded = true
		modelsFound = parseModelsFromJSON(bodyBytes)
		break
	}

	latencyMS := float64(time.Since(start).Microseconds()) / 1000.0

	if !succeeded {
		if lastErr == nil {
			lastErr = errors.New("endpoint probe failed with no response")
		}
		return &ProbeResult{
			Alive:     false,
			LatencyMS: latencyMS,
			Message:   fmt.Sprintf("Failed to reach endpoint %s: %v", cleanURL, lastErr),
		}, lastErr
	}

	// Verify model match
	matched := false
	detected := ""
	if len(modelsFound) > 0 {
		detected = modelsFound[0]
	}

	normExpected := strings.ToLower(strings.TrimSpace(expectedModel))
	for _, m := range modelsFound {
		normM := strings.ToLower(m)
		if normExpected != "" && (normM == normExpected || strings.Contains(normM, normExpected) || strings.Contains(normExpected, normM)) {
			matched = true
			detected = m
			break
		}
	}

	msg := fmt.Sprintf("Endpoint alive (%.1fms)", latencyMS)
	if matched {
		msg += fmt.Sprintf(" - Model verified: %s", detected)
	} else if detected != "" {
		msg += fmt.Sprintf(" - Warning: Expected %q but endpoint is serving %q", expectedModel, detected)
	}

	return &ProbeResult{
		Alive:         true,
		LatencyMS:     latencyMS,
		ModelsFound:   modelsFound,
		ModelMatched:  matched,
		DetectedModel: detected,
		Message:       msg,
	}, nil
}
