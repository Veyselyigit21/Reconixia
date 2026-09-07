package safety

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// NormalizeTarget converts a user supplied target into a strict hostname.
func NormalizeTarget(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return "", false
	}
	if strings.ContainsAny(raw, " ;|'\"`$(){}[]<>\\\n\r\t") {
		return "", false
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", false
		}
		raw = u.Hostname()
	} else {
		raw = strings.Split(raw, "/")[0]
		raw = strings.Split(raw, ":")[0]
	}
	raw = strings.Trim(raw, ".")
	if raw == "" || len(raw) > 253 || isBlockedHostname(raw) {
		return "", false
	}
	if ip := net.ParseIP(raw); ip != nil {
		if !isAllowedIP(ip) {
			return "", false
		}
		return ip.String(), true
	}
	if !hostnameRe.MatchString(raw) {
		return "", false
	}
	return raw, true
}

// IsSafeFetchURL returns true only for http/https URLs that do not point to
// private, loopback, link-local, multicast, unspecified or metadata IP ranges.
func IsSafeFetchURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return isAllowedIP(ip)
	}
	_, ok := NormalizeTarget(host)
	return ok
}

// SafeHTTPClient returns an *http.Client with a custom DialContext that
// resolves hostnames and validates the resulting IP BEFORE connecting.
// FIX: DNS rebinding koruması — ilk DNS sorgusu public IP donerse bile
// gerçek bağlantı anında IP tekrar kontrol ediliyor.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	baseDialer := &net.Dialer{Timeout: timeout}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Resolve then validate — prevents DNS rebinding
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
			if err != nil {
				return nil, err
			}
			for _, a := range ips {
				if !isAllowedIP(a.IP) {
					return nil, &net.AddrError{
						Err:  "blocked: resolved to unsafe/private IP",
						Addr: a.IP.String(),
					}
				}
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func isBlockedHostname(host string) bool {
	if labMode() && (host == "localhost" || host == "localhost.localdomain") {
		return false
	}
	blocked := map[string]bool{
		"localhost":                true,
		"localhost.localdomain":    true,
		"metadata.google.internal": true,
		"169.254.169.254":          true,
		"100.100.100.200":          true,
	}
	if blocked[host] {
		return true
	}
	// DNS rebinding helper services
	for _, suffix := range []string{".nip.io", ".xip.io", ".sslip.io", ".localtest.me", ".lvh.me"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func isUnsafeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || isMetadataIP(ip)
}

func isMetadataIP(ip net.IP) bool {
	for _, m := range []string{"169.254.169.254", "100.100.100.200", "192.0.0.192"} {
		if ip.Equal(net.ParseIP(m)) {
			return true
		}
	}
	return false
}

func isAllowedIP(ip net.IP) bool {
	if ip == nil || isMetadataIP(ip) || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if labMode() {
		return true
	}
	return !isUnsafeIP(ip)
}

func labMode() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("RECONIXIA_LAB_MODE")))
	return v == "1" || v == "true" || v == "yes"
}

// ScopeAllowsURL checks whether a URL hostname is allowed by scope rules.
func ScopeAllowsURL(rawURL string, rules []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return false
	}
	host, ok := NormalizeTarget(u.Hostname())
	if !ok {
		return false
	}
	if denied(host, rules) {
		return false
	}
	for _, r := range rules {
		r = strings.TrimSpace(strings.ToLower(r))
		if r == "" || strings.HasPrefix(r, "#") || strings.HasPrefix(r, "!") {
			continue
		}
		if match(host, r) {
			return true
		}
	}
	return false
}

func denied(host string, rules []string) bool {
	for _, r := range rules {
		r = strings.TrimSpace(strings.ToLower(r))
		if strings.HasPrefix(r, "!") && match(host, strings.TrimPrefix(r, "!")) {
			return true
		}
	}
	return false
}

func match(host, rule string) bool {
	rule = strings.TrimSpace(strings.ToLower(rule))
	if strings.HasPrefix(rule, "*.") {
		base := strings.TrimPrefix(rule, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == rule
}

func FilterSafeScopedURLs(urls []string, rules []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		if IsSafeFetchURL(u) && ScopeAllowsURL(u, rules) {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}
