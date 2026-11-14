package slmprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newMockClient(fn roundTripFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func jsonResponse(statusCode int, body interface{}) *http.Response {
	data, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBuffer(data)),
	}
}

func TestProbe_NoneDetected(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBufferString("not found")),
		}, nil
	})

	prober := NewProber(
		WithTimeout(50*time.Millisecond),
		WithHTTPClient(client),
	)

	start := time.Now()
	res := prober.Probe(context.Background(), "")
	elapsed := time.Since(start)

	if res.Detected {
		t.Errorf("expected Detected=false, got true")
	}
	if res.DetectedProvider != ProviderNone {
		t.Errorf("expected DetectedProvider=none, got %s", res.DetectedProvider)
	}
	if res.ConfiguredActive {
		t.Errorf("expected ConfiguredActive=false, got true")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("probe took too long: %v", elapsed)
	}
}

func TestProbe_PromptGuardDetected(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/health" {
			return jsonResponse(http.StatusOK, promptGuardHealthResponse{
				Status: "healthy",
				Model:  "deberta-v3-base-injection",
			}), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})

	prober := NewProber(
		WithTimeout(100*time.Millisecond),
		WithHTTPClient(client),
		WithPromptGuardURL("http://127.0.0.1:8088/health", "http://127.0.0.1:8088/predict"),
		WithOllamaURL("http://127.0.0.1:11434/api/tags", "http://127.0.0.1:11434"),
	)

	res := prober.Probe(context.Background(), "")
	if !res.Detected {
		t.Fatalf("expected Detected=true")
	}
	if res.DetectedProvider != ProviderPromptGuard {
		t.Errorf("expected DetectedProvider=prompt-guard, got %s", res.DetectedProvider)
	}
	if res.DetectedURL != "http://127.0.0.1:8088/predict" {
		t.Errorf("expected DetectedURL=http://127.0.0.1:8088/predict, got %s", res.DetectedURL)
	}
	if res.ModelName != "deberta-v3-base-injection" {
		t.Errorf("expected ModelName=deberta-v3-base-injection, got %s", res.ModelName)
	}
	if res.LatencyMs < 0 {
		t.Errorf("expected LatencyMs >= 0, got %d", res.LatencyMs)
	}
}

func TestProbe_DockerDetected(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/health" {
			return jsonResponse(http.StatusOK, map[string]string{
				"status": "ok",
			}), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})

	prober := NewProber(
		WithTimeout(100*time.Millisecond),
		WithHTTPClient(client),
		WithPromptGuardURL("http://127.0.0.1:8088/health", "http://127.0.0.1:8088/predict"),
		WithOllamaURL("http://127.0.0.1:11434/api/tags", "http://127.0.0.1:11434"),
	)

	res := prober.Probe(context.Background(), "")
	if !res.Detected {
		t.Fatalf("expected Detected=true")
	}
	if res.DetectedProvider != ProviderDocker {
		t.Errorf("expected DetectedProvider=docker, got %s", res.DetectedProvider)
	}
	if res.DetectedURL != "http://127.0.0.1:8088" {
		t.Errorf("expected DetectedURL=http://127.0.0.1:8088, got %s", res.DetectedURL)
	}
	if res.ModelName != "FaradAiGuard (Docker)" {
		t.Errorf("expected ModelName=FaradAiGuard (Docker), got %s", res.ModelName)
	}
}

func TestProbe_OllamaDetected(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/tags" {
			return jsonResponse(http.StatusOK, ollamaTagsResponse{
				Models: []struct {
					Name  string `json:"name"`
					Model string `json:"model"`
				}{
					{Name: "llama-guard3:1b", Model: "llama-guard3:1b"},
				},
			}), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})

	prober := NewProber(
		WithTimeout(100*time.Millisecond),
		WithHTTPClient(client),
		WithPromptGuardURL("http://127.0.0.1:8088/health", "http://127.0.0.1:8088/predict"),
		WithOllamaURL("http://127.0.0.1:11434/api/tags", "http://127.0.0.1:11434"),
	)

	res := prober.Probe(context.Background(), "")
	if !res.Detected {
		t.Fatalf("expected Detected=true")
	}
	if res.DetectedProvider != ProviderOllama {
		t.Errorf("expected DetectedProvider=ollama, got %s", res.DetectedProvider)
	}
	if res.DetectedURL != "http://127.0.0.1:11434" {
		t.Errorf("expected DetectedURL=http://127.0.0.1:11434, got %s", res.DetectedURL)
	}
	if res.ModelName != "llama-guard3:1b" {
		t.Errorf("expected ModelName=llama-guard3:1b, got %s", res.ModelName)
	}
}

func TestProbe_ConfiguredActive(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == "http://custom-guard:9000/health" {
			return jsonResponse(http.StatusOK, promptGuardHealthResponse{
				Status: "healthy",
				Model:  "custom-guard-model",
			}), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})

	prober := NewProber(
		WithTimeout(100*time.Millisecond),
		WithHTTPClient(client),
	)

	res := prober.Probe(context.Background(), "http://custom-guard:9000/predict")
	if !res.ConfiguredActive {
		t.Fatalf("expected ConfiguredActive=true")
	}
	if res.ConfiguredURL != "http://custom-guard:9000/predict" {
		t.Errorf("expected ConfiguredURL=http://custom-guard:9000/predict, got %s", res.ConfiguredURL)
	}
	if res.ModelName != "custom-guard-model" {
		t.Errorf("expected ModelName=custom-guard-model, got %s", res.ModelName)
	}
}

func TestProbe_TimeoutEnforced(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(1 * time.Second):
			return jsonResponse(http.StatusOK, map[string]string{"status": "ok"}), nil
		}
	})

	prober := NewProber(
		WithTimeout(50*time.Millisecond),
		WithHTTPClient(client),
	)

	start := time.Now()
	res := prober.Probe(context.Background(), "http://hanging:8088/predict")
	elapsed := time.Since(start)

	if res.Detected {
		t.Errorf("expected Detected=false on timeout")
	}
	if res.ConfiguredActive {
		t.Errorf("expected ConfiguredActive=false on timeout")
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("probe did not respect timeout: took %v", elapsed)
	}
}

func TestProbe_PromptGuardPrecedence(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/health" {
			return jsonResponse(http.StatusOK, promptGuardHealthResponse{
				Status: "healthy",
				Model:  "prompt-guard-v2",
			}), nil
		}
		if req.URL.Path == "/api/tags" {
			return jsonResponse(http.StatusOK, ollamaTagsResponse{
				Models: []struct {
					Name  string `json:"name"`
					Model string `json:"model"`
				}{{Name: "llama3", Model: "llama3"}},
			}), nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})

	prober := NewProber(
		WithTimeout(100*time.Millisecond),
		WithHTTPClient(client),
	)

	res := prober.Probe(context.Background(), "")
	if !res.Detected {
		t.Fatalf("expected Detected=true")
	}
	// Prompt-Guard takes precedence when both are responsive
	if res.DetectedProvider != ProviderPromptGuard {
		t.Errorf("expected DetectedProvider=prompt-guard, got %s", res.DetectedProvider)
	}
	if res.ModelName != "prompt-guard-v2" {
		t.Errorf("expected ModelName=prompt-guard-v2, got %s", res.ModelName)
	}
}

func TestDefaultProber_BlocksIMDSAndUnsafeRedirects(t *testing.T) {
	prober := NewProber(WithTimeout(250 * time.Millisecond))

	tests := []struct {
		name      string
		targetURL string
	}{
		{
			name:      "cloud metadata 169.254.169.254 redirect blocked",
			targetURL: "http://169.254.169.254/latest/meta-data/",
		},
		{
			name:      "AWS ECS link-local metadata 169.254.170.2 redirect blocked",
			targetURL: "http://169.254.170.2/v2/credentials",
		},
		{
			name:      "IPv6 link-local fe80::1 redirect blocked",
			targetURL: "http://[fe80::1]:8080/health",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.targetURL, http.StatusFound)
			}))
			defer redirSrv.Close()

			resp, err := prober.client.Get(redirSrv.URL)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("expected redirect to %s to be blocked", tc.targetURL)
			}
			if !strings.Contains(err.Error(), "metadata") && !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "link-local") {
				t.Fatalf("expected SSRF/metadata/link-local error, got: %v", err)
			}
		})
	}
}
