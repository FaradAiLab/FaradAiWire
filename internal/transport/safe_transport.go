package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/config"
)

// Root SSRF egress violation error.
var ErrSSRFBlocked = errors.New("security violation: outbound request blocked by SSRF egress policy")

// Specific security error categories wrapping ErrSSRFBlocked.
var (
	ErrSchemeNotAllowed     = fmt.Errorf("%w: URL scheme not allowed (only HTTP and HTTPS are permitted)", ErrSSRFBlocked)
	ErrDomainNotAllowed     = fmt.Errorf("%w: destination domain is not in the allowlist", ErrSSRFBlocked)
	ErrPrivateIPBlocked     = fmt.Errorf("%w: connection to private/internal IP address is prohibited", ErrSSRFBlocked)
	ErrLoopbackBlocked      = fmt.Errorf("%w: connection to loopback address is prohibited", ErrSSRFBlocked)
	ErrMetadataIPBlocked    = fmt.Errorf("%w: connection to cloud metadata service is prohibited", ErrSSRFBlocked)
	ErrLinkLocalBlocked     = fmt.Errorf("%w: connection to link-local address is prohibited", ErrSSRFBlocked)
	ErrUnspecifiedIPBlocked = fmt.Errorf("%w: connection to unspecified address (0.0.0.0 / ::) is prohibited", ErrSSRFBlocked)
	ErrNoSafeIPFound        = fmt.Errorf("%w: no safe public IP resolved for destination host", ErrSSRFBlocked)
	ErrEmptyHost            = fmt.Errorf("%w: destination host is empty", ErrSSRFBlocked)
)

var (
	metadataIPv4 = net.ParseIP("169.254.169.254")
	metadataIPv6 = net.ParseIP("fd00:ec2::254")

	// Default blocked CIDR blocks representing loopbacks, RFC1918, link-local, cloud metadata, CGNAT, broadcast, multicast.
	defaultBlockedCIDRs []*net.IPNet
)

func init() {
	rawCIDRs := []string{
		// IPv4 Loopback (RFC 1122 / RFC 5735)
		"127.0.0.0/8",
		// IPv4 Private (RFC 1918)
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// IPv4 Shared Address Space / CGNAT (RFC 6598)
		"100.64.0.0/10",
		// IPv4 Link-Local (RFC 3927)
		"169.254.0.0/16",
		// IPv4 "This host on this network" / 0.0.0.0/8
		"0.0.0.0/8",
		// IPv4 Documentation (RFC 5737)
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		// IPv4 Benchmarking (RFC 2544)
		"198.18.0.0/15",
		// IPv4 Multicast (RFC 5771)
		"224.0.0.0/4",
		// IPv4 Limited Broadcast (RFC 919)
		"255.255.255.255/32",

		// IPv6 Loopback (RFC 4291)
		"::1/128",
		// IPv6 Unspecified
		"::/128",
		// IPv6 Unique Local Addresses - ULA (RFC 4193)
		"fc00::/7",
		// IPv6 Link-Local Unicast (RFC 4291)
		"fe80::/10",
		// IPv6 Documentation (RFC 3849)
		"2001:db8::/32",
		// IPv6 Discard-only (RFC 6666)
		"100::/64",
		// IPv6 Multicast (RFC 4291)
		"ff00::/8",
		// Cloud Metadata IPv6 (AWS IMDSv2 IPv6 / OpenStack)
		"fd00:ec2::254/128",
	}

	for _, cidr := range rawCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			defaultBlockedCIDRs = append(defaultBlockedCIDRs, ipNet)
		}
	}
}

// SafeTransportOptions configures the SSRF egress guardrails.
type SafeTransportOptions struct {
	Enabled            bool
	BlockPrivateIPs    bool
	AllowedDomains     []string
	CustomBlockedCIDRs []*net.IPNet
	DialTimeout        time.Duration
	Resolver           *net.Resolver
}

// DefaultSafeOptions returns production-grade default options with all private/metadata ranges blocked.
// If FARADAI_WIRE_ALLOW_LOCAL_TARGETS=true or FARADAI_WIRE_ENV=development is set, private/loopback blocking is relaxed for local development.
func DefaultSafeOptions() SafeTransportOptions {
	blockPrivate := true
	if strings.ToLower(os.Getenv("FARADAI_WIRE_ALLOW_LOCAL_TARGETS")) == "true" || strings.ToLower(os.Getenv("FARADAI_WIRE_ENV")) == "development" {
		blockPrivate = false
	}
	return SafeTransportOptions{
		Enabled:         true,
		BlockPrivateIPs: blockPrivate,
		DialTimeout:     10 * time.Second,
	}
}

// OptionsFromConfig maps configuration structure to SafeTransportOptions.
// Omitted pointer fields default to safe-by-default SSRF guardrails from DefaultSafeOptions.
func OptionsFromConfig(cfg config.SSRFProtectionConfig) SafeTransportOptions {
	opts := DefaultSafeOptions()
	opts.Enabled = cfg.IsEnabled()
	opts.BlockPrivateIPs = cfg.ShouldBlockPrivateIPs(opts.BlockPrivateIPs)
	opts.AllowedDomains = cfg.AllowedDomains
	return opts
}

// IsSafeIP validates an IP address against loopback, private, link-local, cloud metadata, and custom blocked CIDRs.
// Cloud metadata endpoints (169.254.169.254, fd00:ec2::254, IPv4-mapped ::ffff:169.254.169.254)
// are blocked unconditionally even when SSRF Enabled=false or BlockPrivateIPs=false.
func IsSafeIP(ip net.IP, opts SafeTransportOptions) error {
	if ip == nil {
		return fmt.Errorf("%w: nil IP", ErrSSRFBlocked)
	}

	// Unwrap IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	// 1. High-risk Cloud Metadata addresses (AWS, GCP, Azure, OpenStack IMDS) - ALWAYS blocked
	if (metadataIPv4 != nil && ip.Equal(metadataIPv4)) || (metadataIPv6 != nil && ip.Equal(metadataIPv6)) {
		return fmt.Errorf("%w (%s)", ErrMetadataIPBlocked, ip.String())
	}

	if !opts.Enabled {
		return nil
	}

	if !opts.BlockPrivateIPs {
		return nil
	}

	// 2. Loopback & Unspecified interfaces
	if ip.IsLoopback() {
		return fmt.Errorf("%w (%s)", ErrLoopbackBlocked, ip.String())
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("%w (%s)", ErrUnspecifiedIPBlocked, ip.String())
	}

	// 3. Multicast ranges
	if ip.IsMulticast() {
		return fmt.Errorf("%w: multicast IP (%s)", ErrSSRFBlocked, ip.String())
	}

	// 4. Link-Local addresses
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w (%s)", ErrLinkLocalBlocked, ip.String())
	}

	// 5. RFC 1918 & IPv6 ULA Private IP ranges
	if ip.IsPrivate() {
		return fmt.Errorf("%w (%s)", ErrPrivateIPBlocked, ip.String())
	}

	// 6. Explicit Subnet / CIDR checks (covering CGNAT, Documentation, Broadcast, etc.)
	for _, ipNet := range defaultBlockedCIDRs {
		if ipNet.Contains(ip) {
			if strings.HasPrefix(ipNet.String(), "169.254") || strings.HasPrefix(ipNet.String(), "fd00:ec2::254") {
				return fmt.Errorf("%w (%s)", ErrMetadataIPBlocked, ip.String())
			}
			return fmt.Errorf("%w: IP %s matched restricted subnet %s", ErrSSRFBlocked, ip.String(), ipNet.String())
		}
	}

	// 7. Custom operator CIDR blocks
	for _, ipNet := range opts.CustomBlockedCIDRs {
		if ipNet != nil && ipNet.Contains(ip) {
			return fmt.Errorf("%w: IP %s matched custom restricted subnet %s", ErrSSRFBlocked, ip.String(), ipNet.String())
		}
	}

	return nil
}

func isDomainAllowed(host string, allowlist []string) bool {
	lowerHost := strings.ToLower(host)
	for _, domain := range allowlist {
		lowerDomain := strings.ToLower(strings.TrimSpace(domain))
		if lowerDomain == "" {
			continue
		}
		if lowerHost == lowerDomain || strings.HasSuffix(lowerHost, "."+lowerDomain) {
			return true
		}
	}
	return false
}

// ValidateURL checks URL format, scheme, host, and optional domain allowlist.
func ValidateURL(rawURL string, opts SafeTransportOptions) error {
	if rawURL == "" {
		return fmt.Errorf("%w: empty URL", ErrSSRFBlocked)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSRFBlocked, err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: '%s'", ErrSchemeNotAllowed, scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return ErrEmptyHost
	}

	if len(opts.AllowedDomains) > 0 && !isDomainAllowed(host, opts.AllowedDomains) {
		return fmt.Errorf("%w: domain '%s' is not allowed", ErrDomainNotAllowed, host)
	}

	// If host is an IP literal, validate directly using explicit opts (do not bypass BlockPrivateIPs).
	if ip := net.ParseIP(host); ip != nil {
		if err := IsSafeIP(ip, opts); err != nil {
			return err
		}
	}

	return nil
}

// NewSafeTransport creates an http.Transport with DNS resolution validation and socket-level IP enforcement.
// It defends against DNS Rebinding (TOCTOU) by resolving IPs upfront and dialing the validated IP directly.
func NewSafeTransport(opts SafeTransportOptions) *http.Transport {
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid destination address '%s': %w", addr, err)
			}

			if len(opts.AllowedDomains) > 0 && !isDomainAllowed(host, opts.AllowedDomains) {
				return nil, fmt.Errorf("%w: domain '%s' is not in allowlist", ErrDomainNotAllowed, host)
			}

			// Validate IP literal or resolve hostname
			var targetIPs []net.IP
			if ip := net.ParseIP(host); ip != nil {
				if err := IsSafeIP(ip, opts); err != nil {
					return nil, err
				}
				targetIPs = append(targetIPs, ip)
			} else {
				// DNS Resolution with Context
				ipAddrs, err := resolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("DNS resolution failed for '%s': %w", host, err)
				}
				if len(ipAddrs) == 0 {
					return nil, fmt.Errorf("no IP addresses resolved for '%s'", host)
				}

				// ZERO-TRUST SSRF DEFENSE: Verify ALL resolved IPs.
				// If any resolved IP points to private/loopback/metadata range, reject connection immediately.
				for _, ipAddr := range ipAddrs {
					if err := IsSafeIP(ipAddr.IP, opts); err != nil {
						return nil, fmt.Errorf("SSRF violation: host '%s' resolved to blocked IP %s: %w", host, ipAddr.IP.String(), err)
					}
					targetIPs = append(targetIPs, ipAddr.IP)
				}
			}

			if len(targetIPs) == 0 {
				return nil, ErrNoSafeIPFound
			}

			dialer := &net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: 30 * time.Second,
			}

			// Connect directly to the validated safe IP address.
			// This prevents any subsequent DNS rebinding lookup during TCP connection establishment.
			var lastErr error
			for _, ip := range targetIPs {
				targetAddr := net.JoinHostPort(ip.String(), port)
				conn, err := dialer.DialContext(ctx, network, targetAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}

			return nil, fmt.Errorf("failed to connect to host '%s' on port %s: %w", host, port, lastErr)
		},
		TLSHandshakeTimeout:   dialTimeout,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: dialTimeout,
	}
}

// NewSafeHTTPClient creates an http.Client equipped with SafeTransport and redirect security validation.
func NewSafeHTTPClient(opts SafeTransportOptions, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	opts.DialTimeout = timeout

	transport := NewSafeTransport(opts)

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if err := ValidateURL(req.URL.String(), opts); err != nil {
				return fmt.Errorf("redirect blocked by SSRF policy: %w", err)
			}
			if len(via) > 0 && via[0].URL != nil && req.URL != nil {
				orig := via[0].URL
				if strings.EqualFold(orig.Scheme, "https") && strings.EqualFold(req.URL.Scheme, "http") {
					return fmt.Errorf("%w: refusing HTTPS-to-HTTP downgrade redirect", ErrSSRFBlocked)
				}
				if !strings.EqualFold(orig.Scheme, req.URL.Scheme) || !strings.EqualFold(orig.Host, req.URL.Host) {
					for _, h := range []string{"Authorization", "Proxy-Authorization", "X-API-Key", "Api-Key", "X-Auth-Token", "Cookie"} {
						req.Header.Del(h)
					}
				}
			}
			return nil
		},
	}
}

// NewSafeHTTPClientFromConfig creates an http.Client from application configuration.
func NewSafeHTTPClientFromConfig(cfg config.SSRFProtectionConfig, timeout time.Duration) *http.Client {
	opts := OptionsFromConfig(cfg)
	return NewSafeHTTPClient(opts, timeout)
}
