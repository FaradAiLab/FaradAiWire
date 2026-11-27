package settings

import (
	"errors"
	"math"
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
		name    string
		key     string
		strVal  string
		wantVal any
		wantErr bool
		errIs   error
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

func TestProbeTimeoutSec_RegistrationAndBounds(t *testing.T) {
	t.Parallel()

	s := DefaultOperationalSettings()
	if s.Timeouts.ProbeTimeoutSec != 5 {
		t.Fatalf("expected default ProbeTimeoutSec=5, got %d", s.Timeouts.ProbeTimeoutSec)
	}

	if err := Validate("timeouts.probe_timeout_sec", 125); err != nil {
		t.Fatalf("expected 125s probe timeout to be valid, got: %v", err)
	}
	if err := Validate("timeouts.probe_timeout_sec", 0); err == nil {
		t.Fatal("expected 0s probe timeout to fail Min validation")
	}
	if err := Validate("timeouts.probe_timeout_sec", 301); err == nil {
		t.Fatal("expected 301s probe timeout to fail Max validation")
	}

	parsed, err := ParseAndValidate("timeouts.probe_timeout_sec", "15")
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}
	if err := ApplySetting(s, "timeouts.probe_timeout_sec", parsed); err != nil {
		t.Fatalf("ApplySetting failed: %v", err)
	}
	got, err := ExtractSetting(s, "timeouts.probe_timeout_sec")
	if err != nil || got != 15 {
		t.Fatalf("expected ExtractSetting=15, got %v (err=%v)", got, err)
	}
}

func TestTelemetryRetentionAndPreviewSettings(t *testing.T) {
	t.Parallel()

	s := DefaultOperationalSettings()
	if s.Limits.MaxPreviewBytes != 524288 {
		t.Fatalf("expected default MaxPreviewBytes=524288, got %d", s.Limits.MaxPreviewBytes)
	}
	if s.Maintenance.AuditRetentionDays != 30 {
		t.Fatalf("expected default AuditRetentionDays=30, got %d", s.Maintenance.AuditRetentionDays)
	}
	if !s.Maintenance.RetainLocalPayloads {
		t.Fatal("expected default RetainLocalPayloads=true")
	}

	tests := []struct {
		name    string
		key     string
		val     any
		wantErr bool
	}{
		{name: "preview min ok", key: "limits.max_preview_bytes", val: 65536, wantErr: false},
		{name: "preview max ok", key: "limits.max_preview_bytes", val: 4194304, wantErr: false},
		{name: "preview below min", key: "limits.max_preview_bytes", val: 4096, wantErr: true},
		{name: "preview above max", key: "limits.max_preview_bytes", val: 8388608, wantErr: true},
		{name: "retention min ok", key: "maintenance.audit_retention_days", val: 7, wantErr: false},
		{name: "retention max ok", key: "maintenance.audit_retention_days", val: 365, wantErr: false},
		{name: "retention below min", key: "maintenance.audit_retention_days", val: 6, wantErr: true},
		{name: "retention above max", key: "maintenance.audit_retention_days", val: 366, wantErr: true},
		{name: "retain local false ok", key: "maintenance.retain_local_payloads", val: false, wantErr: false},
		{name: "guard threshold NaN rejected", key: "guard.threshold_score", val: math.NaN(), wantErr: true},
		{name: "guard threshold +Inf rejected", key: "guard.threshold_score", val: math.Inf(1), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.key, tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%q, %v) err=%v, wantErr=%v", tc.key, tc.val, err, tc.wantErr)
			}
		})
	}
}

func TestGuardDesktopAlertSettings(t *testing.T) {
	t.Parallel()

	s := DefaultOperationalSettings()
	if !s.Guard.DesktopAlertsEnabled {
		t.Error("expected default DesktopAlertsEnabled=true")
	}
	if !s.Guard.AlertOnGuardOffline {
		t.Error("expected default AlertOnGuardOffline=true")
	}
	if !s.Guard.AlertOnHITLPending {
		t.Error("expected default AlertOnHITLPending=true")
	}
	if !s.Guard.AlertOnBlock {
		t.Error("expected default AlertOnBlock=true")
	}
	if s.Guard.AlertOnAudit {
		t.Error("expected default AlertOnAudit=false")
	}
	if s.Guard.AlertCooldownSec != 60 {
		t.Errorf("expected default AlertCooldownSec=60, got %d", s.Guard.AlertCooldownSec)
	}

	clone := s.Clone()
	clone.Guard.DesktopAlertsEnabled = false
	clone.Guard.AlertOnGuardOffline = false
	clone.Guard.AlertOnHITLPending = false
	clone.Guard.AlertOnBlock = false
	clone.Guard.AlertOnAudit = true
	clone.Guard.AlertCooldownSec = 120

	if !s.Guard.DesktopAlertsEnabled || !s.Guard.AlertOnGuardOffline || !s.Guard.AlertOnHITLPending || !s.Guard.AlertOnBlock || s.Guard.AlertOnAudit || s.Guard.AlertCooldownSec != 60 {
		t.Fatal("mutating cloned desktop alert settings altered original settings")
	}

	validationCases := []struct {
		name    string
		key     string
		val     any
		wantErr bool
		errIs   error
	}{
		{name: "desktop_alerts_enabled bool ok", key: "guard.desktop_alerts_enabled", val: false, wantErr: false},
		{name: "desktop_alerts_enabled invalid type", key: "guard.desktop_alerts_enabled", val: "true", wantErr: true, errIs: ErrInvalidValue},
		{name: "alert_on_guard_offline bool ok", key: "guard.alert_on_guard_offline", val: false, wantErr: false},
		{name: "alert_on_hitl_pending bool ok", key: "guard.alert_on_hitl_pending", val: false, wantErr: false},
		{name: "alert_on_block bool ok", key: "guard.alert_on_block", val: false, wantErr: false},
		{name: "alert_on_audit bool ok", key: "guard.alert_on_audit", val: true, wantErr: false},
		{name: "alert_cooldown_sec min zero ok", key: "guard.alert_cooldown_sec", val: 0, wantErr: false},
		{name: "alert_cooldown_sec mid ok", key: "guard.alert_cooldown_sec", val: 60, wantErr: false},
		{name: "alert_cooldown_sec max ok", key: "guard.alert_cooldown_sec", val: 3600, wantErr: false},
		{name: "alert_cooldown_sec negative rejected", key: "guard.alert_cooldown_sec", val: -1, wantErr: true, errIs: ErrInvalidValue},
		{name: "alert_cooldown_sec above max rejected", key: "guard.alert_cooldown_sec", val: 3601, wantErr: true, errIs: ErrInvalidValue},
		{name: "alert_cooldown_sec float rejected", key: "guard.alert_cooldown_sec", val: 12.5, wantErr: true, errIs: ErrInvalidValue},
	}

	for _, tc := range validationCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			meta, ok := Registry[tc.key]
			if !ok {
				t.Fatalf("missing registry key %q", tc.key)
			}
			if meta.Category != "guard" {
				t.Fatalf("expected category %q for %q, got %q", "guard", tc.key, meta.Category)
			}
			err := Validate(tc.key, tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%q, %v) err=%v, wantErr=%v", tc.key, tc.val, err, tc.wantErr)
			}
			if tc.errIs != nil && !errors.Is(err, tc.errIs) {
				t.Fatalf("Validate(%q, %v) error = %v, want %v", tc.key, tc.val, err, tc.errIs)
			}
		})
	}

	roundTripCases := []struct {
		key  string
		set  any
		want any
	}{
		{key: "guard.desktop_alerts_enabled", set: false, want: false},
		{key: "guard.alert_on_guard_offline", set: false, want: false},
		{key: "guard.alert_on_hitl_pending", set: false, want: false},
		{key: "guard.alert_on_block", set: false, want: false},
		{key: "guard.alert_on_audit", set: true, want: true},
		{key: "guard.alert_cooldown_sec", set: 0, want: 0},
		{key: "guard.alert_cooldown_sec", set: int64(90), want: 90},
		{key: "guard.alert_cooldown_sec", set: float64(180), want: 180},
	}

	for _, tc := range roundTripCases {
		target := DefaultOperationalSettings()
		if err := ApplySetting(target, tc.key, tc.set); err != nil {
			t.Fatalf("ApplySetting(%q, %v) unexpected err: %v", tc.key, tc.set, err)
		}
		got, err := ExtractSetting(target, tc.key)
		if err != nil {
			t.Fatalf("ExtractSetting(%q) unexpected err: %v", tc.key, err)
		}
		if got != tc.want {
			t.Errorf("round-trip %q: got %v (%T), want %v (%T)", tc.key, got, got, tc.want, tc.want)
		}
	}

	// Confirm canonical 4-category invariant remains unchanged.
	cats := map[string]bool{}
	for _, m := range GetAllMetadata() {
		cats[m.Category] = true
	}
	if len(cats) != 4 {
		t.Fatalf("expected exactly 4 categories, got %d (%v)", len(cats), cats)
	}

	// Verify coerceIntSetting rejects NaN/Inf/overflow cleanly and validateMeta enforces Min: 0 on TypeFloat.
	for _, badFloat := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 1e20} {
		target := DefaultOperationalSettings()
		if err := ApplySetting(target, "guard.alert_cooldown_sec", badFloat); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("expected ErrInvalidValue for %v, got %v", badFloat, err)
		}
	}
	floatMeta := SettingMeta{Key: "test.zero_min_float", Type: TypeFloat, Min: 0, Max: 1}
	if err := validateMeta(floatMeta.Key, floatMeta, -0.01); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue for negative float with Min: 0, got %v", err)
	}
}

func TestAuditJSONLAndExportSettings(t *testing.T) {
	t.Parallel()

	s := DefaultOperationalSettings()
	if s.Maintenance.AuditJSONLMaxSizeMB != 10 {
		t.Fatalf("expected default AuditJSONLMaxSizeMB=10, got %d", s.Maintenance.AuditJSONLMaxSizeMB)
	}
	if s.Maintenance.AuditJSONLMaxFiles != 10 {
		t.Fatalf("expected default AuditJSONLMaxFiles=10, got %d", s.Maintenance.AuditJSONLMaxFiles)
	}
	if s.Maintenance.AuditExportMaxRows != 50000 {
		t.Fatalf("expected default AuditExportMaxRows=50000, got %d", s.Maintenance.AuditExportMaxRows)
	}

	clone := s.Clone()
	clone.Maintenance.AuditJSONLMaxSizeMB = 25
	clone.Maintenance.AuditJSONLMaxFiles = 20
	clone.Maintenance.AuditExportMaxRows = 100000
	if s.Maintenance.AuditJSONLMaxSizeMB != 10 || s.Maintenance.AuditJSONLMaxFiles != 10 || s.Maintenance.AuditExportMaxRows != 50000 {
		t.Fatal("mutating cloned audit settings altered original settings")
	}

	cases := []struct {
		name    string
		key     string
		val     any
		wantErr bool
	}{
		{name: "jsonl max size min ok", key: "maintenance.audit_jsonl_max_size_mb", val: 1, wantErr: false},
		{name: "jsonl max size max ok", key: "maintenance.audit_jsonl_max_size_mb", val: 100, wantErr: false},
		{name: "jsonl max size below min", key: "maintenance.audit_jsonl_max_size_mb", val: 0, wantErr: true},
		{name: "jsonl max size above max", key: "maintenance.audit_jsonl_max_size_mb", val: 101, wantErr: true},
		{name: "jsonl max files min ok", key: "maintenance.audit_jsonl_max_files", val: 1, wantErr: false},
		{name: "jsonl max files max ok", key: "maintenance.audit_jsonl_max_files", val: 100, wantErr: false},
		{name: "jsonl max files below min", key: "maintenance.audit_jsonl_max_files", val: 0, wantErr: true},
		{name: "jsonl max files above max", key: "maintenance.audit_jsonl_max_files", val: 101, wantErr: true},
		{name: "export max rows min ok", key: "maintenance.audit_export_max_rows", val: 1000, wantErr: false},
		{name: "export max rows max ok", key: "maintenance.audit_export_max_rows", val: 200000, wantErr: false},
		{name: "export max rows below min", key: "maintenance.audit_export_max_rows", val: 999, wantErr: true},
		{name: "export max rows above max", key: "maintenance.audit_export_max_rows", val: 200001, wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			meta, ok := Registry[tc.key]
			if !ok {
				t.Fatalf("missing registry key %q", tc.key)
			}
			if meta.Category != "maintenance" {
				t.Fatalf("expected maintenance category for %q, got %q", tc.key, meta.Category)
			}
			err := Validate(tc.key, tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%q, %v) err=%v, wantErr=%v", tc.key, tc.val, err, tc.wantErr)
			}
			if !tc.wantErr {
				target := DefaultOperationalSettings()
				if err := ApplySetting(target, tc.key, tc.val); err != nil {
					t.Fatalf("ApplySetting(%q, %v) failed: %v", tc.key, tc.val, err)
				}
				got, err := ExtractSetting(target, tc.key)
				if err != nil || got != tc.val {
					t.Fatalf("ExtractSetting(%q) = %v (%v), want %v", tc.key, got, err, tc.val)
				}
			}
		})
	}
}

func TestRegistry_RequiresRestartAndAlignedBounds(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"timeouts.read_header_timeout_sec",
		"timeouts.idle_timeout_sec",
		"limits.max_scanner_buffer_mb",
	} {
		meta, ok := Registry[key]
		if !ok {
			t.Fatalf("missing key %q", key)
		}
		if !meta.RequiresRestart {
			t.Errorf("expected RequiresRestart=true on %q", key)
		}
	}

	if err := Validate("limits.max_scanner_buffer_mb", 100); err != nil {
		t.Fatalf("expected max_scanner_buffer_mb=100 to be valid: %v", err)
	}
	if err := Validate("limits.max_scanner_buffer_mb", 101); err == nil {
		t.Fatal("expected max_scanner_buffer_mb=101 to fail Max validation")
	}

	if err := Validate("maintenance.correlation_ttl_min", 5); err != nil {
		t.Fatalf("expected correlation_ttl_min=5 to be valid: %v", err)
	}
	if err := Validate("maintenance.correlation_ttl_min", 4); err == nil {
		t.Fatal("expected correlation_ttl_min=4 to fail Min validation")
	}
	if DefaultOperationalSettings().Maintenance.CorrelationTTLMin != 5 {
		t.Fatalf("expected default CorrelationTTLMin=5, got %d", DefaultOperationalSettings().Maintenance.CorrelationTTLMin)
	}

	s := DefaultOperationalSettings()
	if s.Guard.ThresholdScoreOverridden || s.Guard.TimeoutMSOverridden || s.Guard.ColdTimeoutMSOverridden {
		t.Fatal("expected override flags false by default")
	}
	if err := ApplySetting(s, "guard.threshold_score", 0.35); err != nil {
		t.Fatalf("apply threshold_score: %v", err)
	}
	if err := ApplySetting(s, "guard.timeout_ms", 800); err != nil {
		t.Fatalf("apply timeout_ms: %v", err)
	}
	if err := ApplySetting(s, "guard.cold_timeout_ms", 2000); err != nil {
		t.Fatalf("apply cold_timeout_ms: %v", err)
	}
	if !s.Guard.ThresholdScoreOverridden || !s.Guard.TimeoutMSOverridden || !s.Guard.ColdTimeoutMSOverridden {
		t.Fatal("expected override flags to be set after ApplySetting")
	}
	cloned := s.Clone()
	if !cloned.Guard.ThresholdScoreOverridden || !cloned.Guard.TimeoutMSOverridden || !cloned.Guard.ColdTimeoutMSOverridden {
		t.Fatal("expected Clone to preserve guard override flags")
	}
}
