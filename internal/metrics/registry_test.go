package metrics

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistry_CountersHistogramsAndGauges(t *testing.T) {
	reg := NewRegistry()

	reg.ObserveRequest("ALLOWED", "request", "dlp", "fast")
	reg.ObserveRequest("ALLOWED", "request", "dlp", "fast")
	reg.ObserveRequest("BLOCKED", "response", "guard", "deep")

	reg.ObserveFilterDuration("request", "fast", 2*time.Millisecond)
	reg.ObserveFilterDuration("request", "fast", 20*time.Millisecond)
	reg.ObserveUpstreamDuration("http", 35*time.Millisecond)
	reg.ObserveGuardDuration("request", 12*time.Millisecond)
	reg.IncGuardFallback("request")
	reg.IncGuardLoadShed("response")
	reg.IncHTTPResponse("proxy", 200)
	reg.IncHTTPResponse("admin", 401)
	reg.IncRateLimitRejection("proxy")
	reg.IncAuthFailure("admin", "invalid_bearer_token")

	var active atomic.Int64
	active.Store(7)
	reg.SetActiveSessionsProvider(func() int { return int(active.Load()) })
	reg.SetCorrelationEntriesProvider(func() int { return 11 })
	reg.SetDroppedEventsProvider("duckdb", func() uint64 { return 3 })
	reg.AddDroppedEvents("broker", 2)

	out := reg.RenderPrometheus()

	requiredFragments := []string{
		"# HELP faradaiwire_requests_total",
		"# TYPE faradaiwire_requests_total counter",
		`faradaiwire_requests_total{decision="allowed",filter="dlp",path_type="fast",phase="request"} 2`,
		`faradaiwire_requests_total{decision="blocked",filter="guard",path_type="deep",phase="response"} 1`,
		"# TYPE faradaiwire_filter_duration_seconds histogram",
		`faradaiwire_filter_duration_seconds_bucket{path_type="fast",phase="request",le="0.005"} 1`,
		`faradaiwire_filter_duration_seconds_bucket{path_type="fast",phase="request",le="0.025"} 2`,
		`faradaiwire_filter_duration_seconds_bucket{path_type="fast",phase="request",le="+Inf"} 2`,
		`faradaiwire_filter_duration_seconds_count{path_type="fast",phase="request"} 2`,
		`faradaiwire_upstream_duration_seconds_count{transport="http"} 1`,
		`faradaiwire_guard_duration_seconds_count{phase="request"} 1`,
		`faradaiwire_guard_fallback_total{phase="request"} 1`,
		`faradaiwire_guard_load_shed_total{phase="response"} 1`,
		`faradaiwire_telemetry_dropped_events_total{sink="duckdb"} 3`,
		`faradaiwire_telemetry_dropped_events_total{sink="broker"} 2`,
		`faradaiwire_telemetry_dropped_events_total{sink="jsonl"} 0`,
		`faradaiwire_active_sessions 7`,
		`faradaiwire_correlation_entries 11`,
		`faradaiwire_http_responses_total{code_class="2xx",port="proxy"} 1`,
		`faradaiwire_http_responses_total{code_class="4xx",port="admin"} 1`,
		`faradaiwire_rate_limit_rejections_total{port="proxy"} 1`,
		`faradaiwire_auth_failures_total{port="admin",reason="invalid_bearer_token"} 1`,
		"# TYPE faradaiwire_process_uptime_seconds gauge",
		"faradaiwire_process_uptime_seconds ",
	}

	for _, want := range requiredFragments {
		if !strings.Contains(out, want) {
			t.Errorf("expected OpenMetrics output to contain %q\nfull output:\n%s", want, out)
		}
	}
}

func TestRegistry_HighCardinalityLabelsBanned(t *testing.T) {
	reg := NewRegistry()

	// Attempt to smuggle high-cardinality values through filter/decision/reason/port inputs.
	reg.ObserveRequest("CUSTOM_WEIRD_DECISION", "weird_phase", "custom_dlp_rule_ssn_secret_12345", "custom_path")
	reg.IncAuthFailure("9999", "custom_client_ip_10.0.0.42_trace_abc")
	reg.ObserveUpstreamDuration("weird_transport_agent_foo", time.Millisecond)

	out := reg.RenderPrometheus()

	forbiddenKeys := []string{
		"tool_name=",
		"agent_name=",
		"user_id=",
		"trace_id=",
		"client_ip=",
		"rule_name=",
	}
	for _, key := range forbiddenKeys {
		if strings.Contains(out, key) {
			t.Fatalf("high-cardinality label key %q leaked into Prometheus output:\n%s", key, out)
		}
	}

	forbiddenValues := []string{
		"custom_dlp_rule_ssn_secret_12345",
		"custom_client_ip_10.0.0.42_trace_abc",
		"CUSTOM_WEIRD_DECISION",
		"weird_transport_agent_foo",
	}
	for _, val := range forbiddenValues {
		if strings.Contains(out, val) {
			t.Fatalf("unbounded/high-cardinality value %q leaked into Prometheus output:\n%s", val, out)
		}
	}
}

func TestRegistry_ConcurrentSafety(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				reg.ObserveRequest("ALLOWED", "request", "dlp", "fast")
				reg.ObserveFilterDuration("request", "fast", time.Duration(id+i)*time.Microsecond)
				reg.ObserveGuardDuration("response", time.Millisecond)
				reg.ObserveUpstreamDuration("http", time.Millisecond)
				reg.IncHTTPResponse("proxy", 200+(i%4)*100)
				if i%10 == 0 {
					_ = fmt.Sprint(reg.RenderPrometheus())
				}
			}
		}(g)
	}
	wg.Wait()

	out := reg.RenderPrometheus()
	if !strings.Contains(out, `faradaiwire_requests_total{decision="allowed",filter="dlp",path_type="fast",phase="request"} 800`) {
		t.Fatalf("expected 800 concurrent request increments, got:\n%s", out)
	}
}
