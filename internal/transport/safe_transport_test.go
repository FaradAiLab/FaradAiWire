package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

func TestIsSafeIP_BlockedRanges(t *testing.T) {
	opts := DefaultSafeOptions()

	tests := []struct {
		name      string
		ip        string
		expectErr error
	}{
		// IPv4 Loopback
		{"IPv4 Loopback 127.0.0.1", "127.0.0.1", ErrLoopbackBlocked},
		{"IPv4 Loopback 127.0.0.2", "127.0.0.2", ErrLoopbackBlocked},
		{"IPv4 Loopback 127.255.255.254", "127.255.255.254", ErrLoopbackBlocked},

		// IPv6 Loopback
		{"IPv6 Loopback ::1", "::1", ErrLoopbackBlocked},

		// IPv4 Private (RFC 1918)
		{"Private RFC1918 10.0.0.1", "10.0.0.1", ErrPrivateIPBlocked},
		{"Private RFC1918 10.254.0.1", "10.254.0.1", ErrPrivateIPBlocked},
		{"Private RFC1918 172.16.0.1", "172.16.0.1", ErrPrivateIPBlocked},
		{"Private RFC1918 172.31.255.254", "172.31.255.254", ErrPrivateIPBlocked},
		{"Private RFC1918 192.168.1.1", "192.168.1.1", ErrPrivateIPBlocked},
		{"Private RFC1918 192.168.0.254", "192.168.0.254", ErrPrivateIPBlocked},

		// Cloud Metadata & Link-Local IPv4
		{"AWS/Cloud Metadata 169.254.169.254", "169.254.169.254", ErrMetadataIPBlocked},
		{"Link-Local IPv4 169.254.1.1", "169.254.1.1", ErrLinkLocalBlocked},

		// IPv6 Cloud Metadata & Link-Local & ULA
		{"AWS IMDSv2 IPv6 fd00:ec2::254", "fd00:ec2::254", ErrMetadataIPBlocked},
		{"Link-Local IPv6 fe80::1", "fe80::1", ErrLinkLocalBlocked},
		{"IPv6 Unique Local fc00::1", "fc00::1", ErrPrivateIPBlocked},
		{"IPv6 Unique Local fd12:3456:789a::1", "fd12:3456:789a::1", ErrPrivateIPBlocked},

		// CGNAT / Shared Address Space
		{"CGNAT 100.64.0.1", "100.64.0.1", ErrSSRFBlocked},

		// Unspecified / Broadcast / Multicast
		{"Unspecified 0.0.0.0", "0.0.0.0", ErrUnspecifiedIPBlocked},
		{"Unspecified IPv6 ::", "::", ErrUnspecifiedIPBlocked},
		{"Broadcast 255.255.255.255", "255.255.255.255", ErrSSRFBlocked},
		{"Multicast 224.0.0.1", "224.0.0.1", ErrSSRFBlocked},

		// IPv4-mapped IPv6 addresses
		{"IPv4-mapped Loopback ::ffff:127.0.0.1", "::ffff:127.0.0.1", ErrLoopbackBlocked},
		{"IPv4-mapped Private ::ffff:10.0.0.1", "::ffff:10.0.0.1", ErrPrivateIPBlocked},
		{"IPv4-mapped Metadata ::ffff:169.254.169.254", "::ffff:169.254.169.254", ErrMetadataIPBlocked},

		// Safe Public IPs
		{"Cloudflare DNS 1.1.1.1", "1.1.1.1", nil},
		{"Google DNS 8.8.8.8", "8.8.8.8", nil},
		{"Public IPv4 93.184.216.34", "93.184.216.34", nil},
		{"Public IPv6 2606:4700:4700::1111", "2606:4700:4700::1111", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse test IP: %s", tt.ip)
			}
			err := IsSafeIP(ip, opts)
			if tt.expectErr == nil {
				if err != nil {
					t.Errorf("Expected IP %s to be safe, but got error: %v", tt.ip, err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected IP %s to be blocked, but got nil error", tt.ip)
				} else if !errors.Is(err, tt.expectErr) {
					t.Errorf("Expected error wrapping %v, got: %v", tt.expectErr, err)
				}
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	opts := DefaultSafeOptions()

	tests := []struct {
		name        string
		rawURL      string
		expectErr   error
		optsMod     func(opts *SafeTransportOptions)
	}{
		{"Valid Public HTTP", "http://example.com/api", nil, nil},
		{"Valid Public HTTPS", "https://api.github.com/v1", nil, nil},
		{"Empty URL", "", ErrSSRFBlocked, nil},
		{"Invalid Scheme file://", "file:///etc/passwd", ErrSchemeNotAllowed, nil},
		{"Invalid Scheme gopher://", "gopher://127.0.0.1:6379", ErrSchemeNotAllowed, nil},
		{"Invalid Scheme ftp://", "ftp://example.com/file", ErrSchemeNotAllowed, nil},
		{"Invalid Scheme unix://", "unix:///var/run/docker.sock", ErrSchemeNotAllowed, nil},
		{"Blocked IP Literal 169.254.169.254", "http://169.254.169.254/latest/meta-data", ErrMetadataIPBlocked, nil},
		{"Blocked IP Literal 127.0.0.1", "http://127.0.0.1:8080/admin", ErrLoopbackBlocked, nil},
		{"Blocked IP Literal 10.0.0.1", "http://10.0.0.1/status", ErrPrivateIPBlocked, nil},
		{"Blocked IP Literal [::1]", "http://[::1]:8080/sse", ErrLoopbackBlocked, nil},
		{"Allowed Domains Match", "https://allowed.example.com/mcp", nil, func(o *SafeTransportOptions) {
			o.AllowedDomains = []string{"example.com"}
		}},
		{"Allowed Domains Mismatch", "https://evil.com/mcp", ErrDomainNotAllowed, func(o *SafeTransportOptions) {
			o.AllowedDomains = []string{"example.com"}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runOpts := opts
			if tt.optsMod != nil {
				tt.optsMod(&runOpts)
			}

			err := ValidateURL(tt.rawURL, runOpts)
			if tt.expectErr == nil {
				if err != nil {
					t.Errorf("Expected URL '%s' to be valid, got: %v", tt.rawURL, err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected URL '%s' to fail validation, got nil", tt.rawURL)
				} else if !errors.Is(err, tt.expectErr) {
					t.Errorf("Expected error wrapping %v, got: %v", tt.expectErr, err)
				}
			}
		})
	}
}

func TestSafeHTTPClient_BlocksProhibitedDestinations(t *testing.T) {
	opts := DefaultSafeOptions()
	client := NewSafeHTTPClient(opts, 2*time.Second)

	blockedTargets := []struct {
		name string
		url  string
	}{
		{"Cloud Metadata", "http://169.254.169.254/latest/meta-data/"},
		{"Localhost Loopback IP", "http://127.0.0.1:8080/admin"},
		{"RFC 1918 Private IP", "http://10.0.0.1/"},
		{"RFC 1918 172.16 IP", "http://172.16.0.1:9090/"},
		{"RFC 1918 192.168 IP", "http://192.168.1.1/"},
		{"IPv6 Loopback IP", "http://[::1]:8080/"},
		{"Localhost Domain", "http://localhost:8080/"},
	}

	for _, tt := range blockedTargets {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tt.url, nil)
			if err != nil {
				t.Fatalf("Failed to construct request: %v", err)
			}

			_, err = client.Do(req)
			if err == nil {
				t.Fatalf("Security failure: outbound request to '%s' was permitted!", tt.url)
			}

			t.Logf("Successfully blocked '%s' with error: %v", tt.url, err)
		})
	}
}

func TestSafeHTTPClient_OptionsFromConfig(t *testing.T) {
	cfg := config.SSRFProtectionConfig{
		Enabled:         true,
		BlockPrivateIPs: true,
		AllowedDomains:  []string{"trusted.com"},
	}

	client := NewSafeHTTPClientFromConfig(cfg, 3*time.Second)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Should block untrusted domain when allowlist is set
	req, _ := http.NewRequest(http.MethodGet, "http://untrusted.com", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Error("Expected untrusted domain to be blocked by allowlist")
	}
}

func TestSafeTransport_DNSRebindingDefense(t *testing.T) {
	// Simulate DNS rebinding: public looking domain resolving to internal 127.0.0.1 and 169.254.169.254
	opts := DefaultSafeOptions()

	// SafeTransport evaluates resolved IPs in DialContext
	transport := NewSafeTransport(opts)

	// Direct test of transport.DialContext with resolved loopback or private host
	_, err := transport.DialContext(context.Background(), "tcp", "localhost:8080")
	if err == nil {
		t.Fatal("Expected DialContext to fail for localhost due to SSRF defense")
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("Expected error wrapping ErrSSRFBlocked, got: %v", err)
	}
}

func TestSafeTransport_AllowLocalTargetsInDevelopment(t *testing.T) {
	t.Setenv("FARADAI_WIRE_ALLOW_LOCAL_TARGETS", "true")
	opts := DefaultSafeOptions()
	if opts.BlockPrivateIPs {
		t.Error("Expected BlockPrivateIPs to be false when FARADAI_WIRE_ALLOW_LOCAL_TARGETS=true")
	}

	loopbackIP := net.ParseIP("127.0.0.1")
	if err := IsSafeIP(loopbackIP, opts); err != nil {
		t.Errorf("Expected 127.0.0.1 to be allowed in dev mode, got error: %v", err)
	}

	// Cloud metadata must still be strictly blocked even in dev mode
	metadataIP := net.ParseIP("169.254.169.254")
	if err := IsSafeIP(metadataIP, opts); err == nil {
		t.Error("Expected cloud metadata (169.254.169.254) to be blocked even when local targets allowed")
	}
}

