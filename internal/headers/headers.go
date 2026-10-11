package headers

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/researchheaders"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

// versionRe matches a version number like 1.2 or 2.4.57 in a header value.
var versionRe = regexp.MustCompile(`\d+\.\d+`)

type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

// AnalyzeURL performs safe, read-only checks for CORS and common browser security headers.
// It does not attempt exploitation. It sends a simple GET request with a synthetic Origin
// header to observe server policy.
func AnalyzeURL(client *http.Client, rawURL string, rules []string) []Finding {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if !safety.IsSafeFetchURL(rawURL) || !safety.ScopeAllowsURL(rawURL, rules) {
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	researchheaders.Apply(req)
	req.Header.Set("Origin", "https://reconixia.invalid")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var out []Finding
	h := resp.Header
	status := resp.StatusCode

	acao := h.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(h.Get("Access-Control-Allow-Credentials"))
	if acao == "*" && acac == "true" {
		out = append(out, Finding{"cors_wildcard_with_credentials", rawURL, status, "high", "Access-Control-Allow-Origin '*' ve credentials true birlikte görünüyor; manuel doğrula"})
	} else if strings.EqualFold(acao, "https://reconixia.invalid") {
		out = append(out, Finding{"cors_origin_reflection", rawURL, status, "medium", "Origin header yansıtılıyor olabilir; manuel doğrula"})
	} else if acao == "*" {
		out = append(out, Finding{"cors_wildcard", rawURL, status, "low", "Wildcard CORS görüldü; hassas endpointlerde manuel değerlendir"})
	}

	missing := []struct {
		Header string
		Type   string
		Note   string
	}{
		{"Strict-Transport-Security", "missing_hsts", "HSTS header yok; HTTPS downgrade/transport hardening açısından incele"},
		{"Content-Security-Policy", "missing_csp", "CSP header yok; XSS etkisini azaltma açısından incele"},
		{"X-Frame-Options", "missing_x_frame_options", "Clickjacking koruması eksik olabilir"},
		{"X-Content-Type-Options", "missing_x_content_type_options", "nosniff header yok; MIME sniffing açısından incele"},
		{"Referrer-Policy", "missing_referrer_policy", "Referrer policy yok; bilgi sızıntısı açısından incele"},
		{"Cross-Origin-Opener-Policy", "missing_coop", "COOP header yok; cross-origin isolation açısından incele"},
		{"Permissions-Policy", "missing_permissions_policy", "Permissions-Policy yok; tarayıcı özellik yüzeyi kısıtlanmamış"},
	}
	for _, m := range missing {
		if h.Get(m.Header) == "" {
			out = append(out, Finding{m.Type, rawURL, status, "info", m.Note})
		}
	}

	// Sürüm bilgisi ifşası (bilgi sızıntısı; CVE eşleştirme kolaylaşır).
	for _, hk := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime"} {
		v := h.Get(hk)
		if v != "" && versionRe.MatchString(v) {
			out = append(out, Finding{"version_disclosure", rawURL, status, "low", hk + " sürüm bilgisi sızdırıyor: " + v})
		}
	}

	if csp := h.Get("Content-Security-Policy"); csp != "" {
		out = append(out, analyzeCSP(rawURL, status, csp)...)
	}

	return out
}

// analyzeCSP flags common CSP weaknesses: unsafe-inline/eval, wildcard sources,
// and missing object-src / frame-ancestors hardening.
func analyzeCSP(rawURL string, status int, csp string) []Finding {
	var out []Finding
	lcsp := strings.ToLower(csp)
	scriptSrc := cspDirective(lcsp, "script-src")
	if scriptSrc == "" {
		scriptSrc = cspDirective(lcsp, "default-src")
	}
	if strings.Contains(scriptSrc, "unsafe-inline") || strings.Contains(scriptSrc, "unsafe-eval") {
		out = append(out, Finding{"weak_csp", rawURL, status, "low", "CSP script-src içinde unsafe-inline/unsafe-eval; XSS azaltımı zayıf"})
	}
	for _, tok := range strings.Fields(scriptSrc) {
		if tok == "*" || tok == "http:" || tok == "https:" || strings.HasPrefix(tok, "http://*") || strings.HasPrefix(tok, "https://*") {
			out = append(out, Finding{"weak_csp_wildcard", rawURL, status, "low", "CSP script-src aşırı geniş kaynak içeriyor: " + tok})
			break
		}
	}
	if !strings.Contains(lcsp, "object-src") && !strings.Contains(cspDirective(lcsp, "default-src"), "'none'") {
		out = append(out, Finding{"csp_missing_object_src", rawURL, status, "info", "CSP object-src 'none' yok; eklenti/obje tabanlı XSS yüzeyi kısıtlanmamış"})
	}
	if !strings.Contains(lcsp, "frame-ancestors") {
		out = append(out, Finding{"csp_missing_frame_ancestors", rawURL, status, "info", "CSP frame-ancestors yok; clickjacking koruması CSP tarafında eksik"})
	}
	return out
}

// cspDirective returns the sources listed for a CSP directive (lowercased input).
func cspDirective(lcsp, directive string) string {
	for _, part := range strings.Split(lcsp, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, directive+" ") || part == directive {
			return strings.TrimSpace(strings.TrimPrefix(part, directive))
		}
	}
	return ""
}

func FormatFinding(f Finding) string {
	return fmt.Sprintf("%s | %d | %s | %s | %s", f.URL, f.Status, f.Type, f.Confidence, f.Note)
}
