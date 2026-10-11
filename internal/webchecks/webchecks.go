// Package webchecks adds light, non-destructive active checks and passive
// parameter-risk flagging that a recon pass can safely perform: dangerous HTTP
// methods, open redirects, host-header handling, exposed VCS/config/backup
// files, and SSRF/LFI/open-redirect candidate parameters. Every request goes
// through the SSRF-safe, scope-gated layer and uses the research header.
package webchecks

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Veyselyigit21/Reconixia/internal/researchheaders"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

// param name sets for passive risk flagging.
var (
	ssrfParams     = words("url uri dest destination proxy fetch callback webhook feed host site html page domain out image_url imageurl img load open remote source redirect_uri target")
	lfiParams      = words("file path filename doc document folder root pg style template include inc dir show cat read download page_path view content")
	redirectParams = words("next url redirect redirect_uri redir return returnurl return_to continue dest destination goto r u target forward out to rurl checkout_url")
)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// ParamRiskCandidates passively flags URLs whose query parameters match known
// SSRF / LFI / open-redirect sink names. It sends no traffic.
func ParamRiskCandidates(urls []string) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u == nil {
			continue
		}
		for p := range u.Query() {
			lp := strings.ToLower(p)
			var ftype, note string
			switch {
			case ssrfParams[lp]:
				ftype, note = "ssrf_candidate", "parametre '"+p+"' SSRF sink adayı; owned OAST ile manuel doğrula"
			case redirectParams[lp]:
				ftype, note = "open_redirect_candidate", "parametre '"+p+"' open-redirect sink adayı; harici hedefe yönlenmeyi manuel doğrula"
			case lfiParams[lp]:
				ftype, note = "lfi_candidate", "parametre '"+p+"' LFI/path-traversal sink adayı; manuel doğrula"
			default:
				continue
			}
			key := ftype + "|" + u.Host + u.Path + "|" + lp
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{ftype, raw, 0, "low", note})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// DangerousMethods flags hosts that advertise or accept risky HTTP methods
// (TRACE/TRACK → XST, PUT/DELETE/CONNECT). Read-only: it never sends a body.
func DangerousMethods(ctx context.Context, client *http.Client, bases []string, rules []string) []Finding {
	var out []Finding
	for _, base := range scoped(bases, rules) {
		// OPTIONS advertises allowed methods.
		if allow := methodAllow(ctx, client, base); allow != "" {
			up := strings.ToUpper(allow)
			risky := []string{}
			for _, m := range []string{"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"} {
				if strings.Contains(up, m) {
					risky = append(risky, m)
				}
			}
			if len(risky) > 0 {
				out = append(out, Finding{"dangerous_http_methods", base, 0, "low", "OPTIONS izinli riskli metodlar: " + strings.Join(risky, ", ") + "; manuel doğrula"})
			}
		}
		// Active TRACE probe (XST) — no body, just method.
		if st := methodStatus(ctx, client, http.MethodTrace, base); st >= 200 && st < 300 {
			out = append(out, Finding{"http_trace_enabled", base, st, "medium", "TRACE etkin (Cross-Site Tracing riski); devre dışı bırakılmalı"})
		}
	}
	return out
}

// OpenRedirect replaces redirect-ish parameter values with a benign external
// marker and flags responses that redirect to that external host.
func OpenRedirect(ctx context.Context, client *http.Client, candidates []string, rules []string, max int) []Finding {
	const marker = "reconixia-oredir.example"
	nc := noRedirect(client)
	var out []Finding
	n := 0
	for _, raw := range scoped(candidates, rules) {
		if max > 0 && n >= max {
			break
		}
		u, err := url.Parse(raw)
		if err != nil || u == nil {
			continue
		}
		q := u.Query()
		touched := false
		for p := range q {
			if redirectParams[strings.ToLower(p)] {
				q.Set(p, "https://"+marker+"/")
				touched = true
			}
		}
		if !touched {
			continue
		}
		u.RawQuery = q.Encode()
		test := u.String()
		if !safety.IsSafeFetchURL(test) || !safety.ScopeAllowsURL(test, rules) {
			continue
		}
		n++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, test, nil)
		if err != nil {
			continue
		}
		researchheaders.Apply(req)
		resp, err := nc.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && redirectsTo(loc, marker) {
			out = append(out, Finding{"open_redirect", test, resp.StatusCode, "high", "harici hedefe yönlendirme doğrulandı (Location=" + loc + "); owned marker ile tetiklendi"})
		}
	}
	return out
}

// HostHeaderInjection sends a bogus Host and flags when the app reflects it in
// a redirect Location or absolute link rather than rejecting the request.
func HostHeaderInjection(ctx context.Context, client *http.Client, bases []string, rules []string) []Finding {
	const evil = "reconixia-hhi.example"
	nc := noRedirect(client)
	var out []Finding
	for _, base := range scoped(bases, rules) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
		if err != nil {
			continue
		}
		researchheaders.Apply(req)
		req.Host = evil
		resp, err := nc.Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if strings.Contains(strings.ToLower(loc), evil) {
			out = append(out, Finding{"host_header_injection", base, resp.StatusCode, "medium", "uydurma Host değeri Location'a yansıdı (" + loc + "); cache poisoning/redirect açısından manuel doğrula"})
		}
	}
	return out
}

var sensitiveFiles = []struct {
	Path string
	Sig  func(body, ctype string) bool
}{
	{".git/HEAD", func(b, c string) bool { return strings.HasPrefix(strings.TrimSpace(b), "ref:") }},
	{".git/config", func(b, c string) bool { return strings.Contains(b, "[core]") }},
	{".env", func(b, c string) bool { return envLike(b, c) }},
	{".env.local", func(b, c string) bool { return envLike(b, c) }},
	{".env.production", func(b, c string) bool { return envLike(b, c) }},
	{".svn/entries", func(b, c string) bool { return strings.Contains(b, "dir") || strings.TrimSpace(b) != "" && !isHTML(c) }},
	{".DS_Store", func(b, c string) bool { return strings.Contains(b, "Bud1") }},
	{"web.config", func(b, c string) bool { return strings.Contains(strings.ToLower(b), "<configuration") }},
	{"appsettings.json", func(b, c string) bool {
		return strings.Contains(b, "{") && strings.Contains(strings.ToLower(c), "json")
	}},
	{"phpinfo.php", func(b, c string) bool { return strings.Contains(b, "phpinfo()") || strings.Contains(b, "PHP Version") }},
	{"server-status", func(b, c string) bool { return strings.Contains(b, "Apache Server Status") }},
	{"actuator/env", func(b, c string) bool {
		return strings.Contains(b, "activeProfiles") || strings.Contains(b, "propertySources")
	}},
	{".htpasswd", func(b, c string) bool { return strings.Contains(b, ":$") || strings.Contains(b, ":{") }},
	{"backup.zip", func(b, c string) bool { return strings.HasPrefix(b, "PK") }},
	{"dump.sql", func(b, c string) bool {
		return strings.Contains(strings.ToUpper(b), "INSERT INTO") || strings.Contains(strings.ToUpper(b), "CREATE TABLE")
	}},
}

// SensitiveFiles probes for exposed VCS/config/backup files and confirms each
// with a content signature so soft-404s and HTML error pages are not reported.
func SensitiveFiles(ctx context.Context, client *http.Client, bases []string, rules []string) []Finding {
	var out []Finding
	for _, base := range scoped(bases, rules) {
		for _, sf := range sensitiveFiles {
			u := strings.TrimRight(base, "/") + "/" + sf.Path
			if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				continue
			}
			researchheaders.Apply(req)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != 200 {
				resp.Body.Close()
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 65_536))
			ctype := resp.Header.Get("Content-Type")
			resp.Body.Close()
			if sf.Sig(string(b), ctype) {
				out = append(out, Finding{"sensitive_file_exposure", u, 200, "high", "hassas dosya içerik imzasıyla doğrulandı: " + sf.Path + "; değerleri dışarı aktarma, manuel incele"})
			}
		}
	}
	return out
}

// ── helpers ──────────────────────────────────────────────────────────────────

func scoped(urls, rules []string) []string {
	return safety.FilterSafeScopedURLs(urls, rules)
}

func noRedirect(client *http.Client) *http.Client {
	nc := *client
	nc.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	return &nc
}

func methodAllow(ctx context.Context, client *http.Client, u string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, u, nil)
	if err != nil {
		return ""
	}
	researchheaders.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return resp.Header.Get("Allow")
}

func methodStatus(ctx context.Context, client *http.Client, method, u string) int {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0
	}
	researchheaders.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func redirectsTo(location, marker string) bool {
	location = strings.TrimSpace(location)
	if location == "" {
		return false
	}
	if u, err := url.Parse(location); err == nil && u.Host != "" {
		return strings.EqualFold(u.Host, marker)
	}
	// Scheme-relative (//marker/...) or raw host.
	return strings.HasPrefix(location, "//"+marker) || strings.Contains(location, "://"+marker)
}

func envLike(b, c string) bool {
	if isHTML(c) {
		return false
	}
	lines := strings.Split(b, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if eq := strings.Index(l, "="); eq > 0 && strings.ToUpper(l[:eq]) == l[:eq] {
			return true
		}
	}
	return false
}

func isHTML(ctype string) bool {
	return strings.Contains(strings.ToLower(ctype), "text/html")
}
