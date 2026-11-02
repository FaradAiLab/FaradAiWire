package settings

import (
	"errors"
	"testing"
)

func TestDefaultOperationalSettings(t *testing.T) {
	t.Parallel()

	s := DefaultOperationalSettings()
	if s == nil {
		t.Fatal("expected non-nil default settings")
	}

	if s.Limits.MaxPayloadBytes != 10*1024*1024 {
		t.Errorf("expected 10MB payload, got %d", s.Limits.MaxPayloadBytes)
	}
	if s.Guard.ThresholdScore != 0.50 {
		t.Errorf("expected 0.50 threshold, got %v", s.Guard.ThresholdScore)
	}
	if s.Timeouts.ToolExecutionTimeoutSec != 60 {
		t.Errorf("expected 60s timeout, got %d", s.Timeouts.ToolExecutionTimeoutSec)
	}
}

func TestCloneOperationalSettings(t *testing.T) {
	t.Parallel()

	orig := DefaultOperationalSettings()
	clone := orig.Clone()

	if clone == nil {
		t.Fatal("expected non-nil clone")
	}

	// Mutate clone and assert original is not mutated
	clone.Limits.MaxPayloadBytes = 50 * 1024 * 1024
	clone.Guard.ThresholdScore = 0.85

	if orig.Limits.MaxPayloadBytes == clone.Limits.MaxPayloadBytes {
		t.Errorf("expected original limits to be untouched, got %d", orig.Limits.MaxPayloadBytes)
	}
	if orig.Guard.ThresholdScore == clone.Guard.ThresholdScore {
		t.Errorf("expected original threshold to be untouched, got %v", orig.Guard.ThresholdScore)
	}

	// Nil clone returns defaults
	var nilSettings *OperationalSettings
	if nilSettings.Clone() == nil {
		t.Error("expected non-nil default from nil clone")
	}
}

func TestRegistryValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		value   any
		wantErr bool
		errIs   error
	}{
		{
			name:    "valid max_payload_bytes",
			key:     "limits.max_payload_bytes",
			value:   int64(20 * 1024 * 1024),
			wantErr: false,
		},
		{
			name:    "max_payload_bytes below min",
			key:     "limits.max_payload_bytes",
			value:   int64(512), // min is 1024
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "max_payload_bytes above max",
			key:     "limits.max_payload_bytes",
			value:   int64(200 * 1024 * 1024), // max is 100MB
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "valid guard threshold",
			key:     "guard.threshold_score",
			value:   0.35,
			wantErr: false,
		},
		{
			name:    "guard threshold below min",
			key:     "guard.threshold_score",
			value:   0.01, // min is 0.05
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "guard threshold above max",
			key:     "guard.threshold_score",
			value:   0.99, // max is 0.95
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "unknown setting key",
			key:     "nonexistent.setting",
			value:   123,
			wantErr: true,
			errIs:   ErrUnknownSetting,
		},
		{
			name:    "invalid type for int setting",
			key:     "limits.max_scanner_buffer_mb",
			value:   "ten",
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "invalid type for float setting",
			key:     "guard.threshold_score",
			value:   "invalid_score",
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tt.key, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate(%q, %v) error = %v, wantErr %v", tt.key, tt.value, err, tt.wantErr)
			}
			if tt.wantErr && tt.errIs != nil && !errors.Is(err, tt.errIs) {
				t.Errorf("Validate(%q, %v) error = %v, expected error is %v", tt.key, tt.value, err, tt.errIs)
			}
		})
	}
}

func TestParseAndValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		strVal    string
		wantVal   any
		wantErr   bool
		errIs     error
	}{
		{
			name:    "valid parse int",
			key:     "timeouts.tool_execution_sec",
			strVal:  "120",
			wantVal: int64(120),
			wantErr: false,
		},
		{
			name:    "valid parse float",
			key:     "guard.threshold_score",
			strVal:  "0.65",
			wantVal: 0.65,
			wantErr: false,
		},
		{
			name:    "malformed int string",
			key:     "timeouts.tool_execution_sec",
			strVal:  "not_a_number",
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "out of bounds parsed int",
			key:     "timeouts.tool_execution_sec",
			strVal:  "99999",
			wantErr: true,
			errIs:   ErrInvalidValue,
		},
		{
			name:    "unknown key parsing",
			key:     "system.unknown",
			strVal:  "10",
			wantErr: true,
			errIs:   ErrUnknownSetting,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAndValidate(tt.key, tt.strVal)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAndValidate(%q, %q) error = %v, wantErr %v", tt.key, tt.strVal, err, tt.wantErr)
			}
			if tt.wantErr && tt.errIs != nil && !errors.Is(err, tt.errIs) {
				t.Errorf("ParseAndValidate(%q, %q) error = %v, expected error is %v", tt.key, tt.strVal, err, tt.errIs)
			}
			if !tt.wantErr && got != tt.wantVal {
				t.Errorf("ParseAndValidate(%q, %q) got = %v, want = %v", tt.key, tt.strVal, got, tt.wantVal)
			}
		})
	}
}

func TestApplyAndExtractSetting(t *testing.T) {
	t.Parallel()

	s := DefaultOperationalSettings()

	// Apply and extract payload bytes
	err := ApplySetting(s, "limits.max_payload_bytes", int64(25*1024*1024))
	if err != nil {
		t.Fatalf("unexpected error applying setting: %v", err)
	}
	val, err := ExtractSetting(s, "limits.max_payload_bytes")
	if err != nil {
		t.Fatalf("unexpected error extracting setting: %v", err)
	}
	if val != int64(25*1024*1024) {
		t.Errorf("expected 25MB, got %v", val)
	}

	// Apply and extract threshold score
	err = ApplySetting(s, "guard.threshold_score", 0.75)
	if err != nil {
		t.Fatalf("unexpected error applying setting: %v", err)
	}
	val, err = ExtractSetting(s, "guard.threshold_score")
	if err != nil {
		t.Fatalf("unexpected error extracting setting: %v", err)
	}
	if val != 0.75 {
		t.Errorf("expected 0.75, got %v", val)
	}

	// Unknown setting returns error
	err = ApplySetting(s, "unknown.key", 123)
	if !errors.Is(err, ErrUnknownSetting) {
		t.Errorf("expected ErrUnknownSetting, got %v", err)
	}
	_, err = ExtractSetting(s, "unknown.key")
	if !errors.Is(err, ErrUnknownSetting) {
		t.Errorf("expected ErrUnknownSetting, got %v", err)
	}
}

func TestGetAllMetadata(t *testing.T) {
	t.Parallel()

	meta := GetAllMetadata()
	if len(meta) != len(Registry) {
		t.Fatalf("expected %d metadata entries, got %d", len(Registry), len(meta))
	}

	// Verify deterministic sorting: category, then key
	for i := 1; i < len(meta); i++ {
		prev := meta[i-1]
		curr := meta[i]
		if prev.Category > curr.Category {
			t.Errorf("metadata not sorted by category: %s > %s", prev.Category, curr.Category)
		} else if prev.Category == curr.Category && prev.Key > curr.Key {
			t.Errorf("metadata within category not sorted by key: %s > %s", prev.Key, curr.Key)
		}
	}
}
