package slmprobe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPullModel_Success(t *testing.T) {
	streamData := strings.Join([]string{
		`{"status": "pulling manifest"}`,
		`{"status": "downloading layer", "digest": "sha256:1234", "total": 1000, "completed": 250}`,
		`{"status": "downloading layer", "digest": "sha256:1234", "total": 1000, "completed": 1000}`,
		`{"status": "verifying sha256 digest"}`,
		`{"status": "success"}`,
	}, "\n") + "\n"

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			return &http.Response{StatusCode: http.StatusMethodNotAllowed}, nil
		}
		if !strings.HasSuffix(req.URL.Path, "/api/pull") {
			return &http.Response{StatusCode: http.StatusNotFound}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/x-ndjson"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(streamData))),
		}, nil
	})

	puller := NewPuller(WithPullerHTTPClient(client))

	var events []PullProgress
	err := puller.Pull(context.Background(), "http://127.0.0.1:11434", "hf.co/faradailab/guard-qwen3guard", func(p PullProgress) {
		events = append(events, p)
	})

	if err != nil {
		t.Fatalf("Pull failed: %v", err)
	}

	if len(events) != 5 {
		t.Fatalf("expected 5 progress events, got %d", len(events))
	}

	if events[0].Status != "pulling manifest" {
		t.Errorf("expected first event status 'pulling manifest', got '%s'", events[0].Status)
	}

	if events[1].Percent != 25.0 {
		t.Errorf("expected 25%% percent, got %f", events[1].Percent)
	}

	if events[2].Percent != 100.0 {
		t.Errorf("expected 100%% percent, got %f", events[2].Percent)
	}

	if events[4].Status != "success" {
		t.Errorf("expected last event status 'success', got '%s'", events[4].Status)
	}
}

func TestPullModel_ErrorFromOllama(t *testing.T) {
	streamData := `{"error": "repository faradailab/unknown not found"}` + "\n"

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(streamData))),
		}, nil
	})

	puller := NewPuller(WithPullerHTTPClient(client))

	err := puller.Pull(context.Background(), "http://127.0.0.1:11434", "hf.co/faradailab/unknown", nil)
	if err == nil {
		t.Fatalf("expected error from Ollama error stream, got nil")
	}

	if !strings.Contains(err.Error(), "faradailab/unknown not found") {
		t.Errorf("expected error message to contain model name, got: %v", err)
	}
}

func TestPullModel_ContextCancelled(t *testing.T) {
	pipeR, pipeW := io.Pipe()

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       pipeR,
		}, nil
	})

	puller := NewPuller(WithPullerHTTPClient(client))

	ctx, cancel := context.WithCancel(context.Background())

	var received atomic.Int32
	errCh := make(chan error, 1)

	go func() {
		errCh <- puller.Pull(ctx, "http://127.0.0.1:11434", "hf.co/faradailab/guard-laya", func(p PullProgress) {
			received.Add(1)
		})
	}()

	// Write one event
	_, _ = pipeW.Write([]byte("{\"status\": \"pulling\"}\n"))
	time.Sleep(20 * time.Millisecond)

	// Cancel context
	cancel()
	_ = pipeW.Close()

	select {
	case err := <-errCh:
		if err == nil || (!errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled")) {
			t.Fatalf("expected context canceled error, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for Pull to abort on cancelled context")
	}
}

func TestPullModel_InvalidURLScheme(t *testing.T) {
	puller := NewPuller()
	err := puller.Pull(context.Background(), "ftp://127.0.0.1:11434", "model-name", nil)
	if err == nil {
		t.Fatalf("expected error on invalid URL scheme, got nil")
	}
}

func TestPullModel_InvalidModelName(t *testing.T) {
	puller := NewPuller()
	err := puller.Pull(context.Background(), "http://127.0.0.1:11434", "../../../etc/passwd", nil)
	if err == nil {
		t.Fatalf("expected error on invalid model name, got nil")
	}
}
