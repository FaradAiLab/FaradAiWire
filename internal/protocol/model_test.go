package protocol

import (
	"slices"
	"testing"
)

func TestPreserveMaskedSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		incoming      string
		existing      string
		fillWhenEmpty bool
		want          string
	}{
		{
			name:          "masked placeholder restores existing",
			incoming:      "sec" + SecretMaskPlaceholder + "et",
			existing:      "secret-value-123",
			fillWhenEmpty: false,
			want:          "secret-value-123",
		},
		{
			name:          "short placeholder restores existing",
			incoming:      SecretMaskPlaceholder,
			existing:      "tiny",
			fillWhenEmpty: false,
			want:          "tiny",
		},
		{
			name:          "empty preserves empty when fillWhenEmpty is false",
			incoming:      "",
			existing:      "secret-value-123",
			fillWhenEmpty: false,
			want:          "",
		},
		{
			name:          "empty restores existing when fillWhenEmpty is true",
			incoming:      "",
			existing:      "secret-value-123",
			fillWhenEmpty: true,
			want:          "secret-value-123",
		},
		{
			name:          "explicit new token overwrites existing",
			incoming:      "new-rotated-secret",
			existing:      "secret-value-123",
			fillWhenEmpty: true,
			want:          "new-rotated-secret",
		},
		{
			name:          "env placeholder preserved verbatim",
			incoming:      "${MY_TOKEN}",
			existing:      "secret-value-123",
			fillWhenEmpty: false,
			want:          "${MY_TOKEN}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := PreserveMaskedSecret(tc.incoming, tc.existing, tc.fillWhenEmpty); got != tc.want {
				t.Fatalf("PreserveMaskedSecret(%q, %q, %v) = %q, want %q", tc.incoming, tc.existing, tc.fillWhenEmpty, got, tc.want)
			}
		})
	}
}

func TestMergeMaskedEnv(t *testing.T) {
	t.Parallel()

	src := []string{
		"API_KEY=real-api-key-999",
		"PLAIN_VAR=hello",
		"MALFORMED_NO_EQUALS",
	}

	t.Run("restores masked values and keeps rotations", func(t *testing.T) {
		t.Parallel()
		dst := []string{
			"API_KEY=rea" + SecretMaskPlaceholder + "99",
			"PLAIN_VAR=updated",
			"NEW_KEY=brand-new",
			"MALFORMED_NO_EQUALS",
		}
		got := MergeMaskedEnv(dst, src, false)
		want := []string{
			"API_KEY=real-api-key-999",
			"PLAIN_VAR=updated",
			"NEW_KEY=brand-new",
			"MALFORMED_NO_EQUALS",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("MergeMaskedEnv() = %v, want %v", got, want)
		}
	})

	t.Run("fillWhenEmpty clones src when dst is empty", func(t *testing.T) {
		t.Parallel()
		got := MergeMaskedEnv(nil, src, true)
		if !slices.Equal(got, src) {
			t.Fatalf("MergeMaskedEnv(nil, src, true) = %v, want %v", got, src)
		}
		got[0] = "MUTATED=1"
		if src[0] != "API_KEY=real-api-key-999" {
			t.Fatal("expected returned slice to be independent of src")
		}
	})

	t.Run("empty dst stays empty when fillWhenEmpty is false", func(t *testing.T) {
		t.Parallel()
		if got := MergeMaskedEnv(nil, src, false); len(got) != 0 {
			t.Fatalf("expected empty env, got %v", got)
		}
	})
}

func TestMergeMaskedHeaders(t *testing.T) {
	t.Parallel()

	src := map[string]string{
		"Authorization": "Bearer secret-abc-123",
		"X-Trace":       "enabled",
	}

	t.Run("restores masked header and keeps new header", func(t *testing.T) {
		t.Parallel()
		dst := map[string]string{
			"Authorization": "Bea" + SecretMaskPlaceholder + "23",
			"X-Trace":       "custom",
			"X-New":         "1",
		}
		got := MergeMaskedHeaders(dst, src, false)
		if got["Authorization"] != "Bearer secret-abc-123" {
			t.Fatalf("expected restored Authorization, got %q", got["Authorization"])
		}
		if got["X-Trace"] != "custom" || got["X-New"] != "1" {
			t.Fatalf("unexpected non-masked headers: %v", got)
		}
	})

	t.Run("fillWhenEmpty clones src when dst is empty", func(t *testing.T) {
		t.Parallel()
		got := MergeMaskedHeaders(nil, src, true)
		if got["Authorization"] != src["Authorization"] {
			t.Fatalf("expected cloned headers, got %v", got)
		}
		got["Authorization"] = "changed"
		if src["Authorization"] != "Bearer secret-abc-123" {
			t.Fatal("expected returned map to be independent of src")
		}
	})
}

func TestProtocol_HydrateMaskedSecrets_RoundTrip(t *testing.T) {
	t.Parallel()

	existing := &Protocol{
		ID:        "github",
		Name:      "GitHub",
		Type:      "http",
		AuthToken: "ghp_supersecret12345",
		Env:       []string{"GITHUB_TOKEN=ghp_envsecret98765", "LOG_LEVEL=info"},
		Headers:   map[string]string{"X-API-Key": "hdr_secret_54321", "X-Env": "prod"},
	}

	masked := existing.MaskSecrets()
	masked.Headers["X-Env"] = "staging" // non-secret modified by caller
	masked.HydrateMaskedSecrets(existing)

	if masked.AuthToken != existing.AuthToken {
		t.Fatalf("AuthToken = %q, want %q", masked.AuthToken, existing.AuthToken)
	}
	if !slices.Equal(masked.Env, existing.Env) {
		t.Fatalf("Env = %v, want %v", masked.Env, existing.Env)
	}
	if masked.Headers["X-API-Key"] != "hdr_secret_54321" || masked.Headers["X-Env"] != "staging" {
		t.Fatalf("unexpected Headers after hydration: %v", masked.Headers)
	}
}
