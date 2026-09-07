package headers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

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
	}
	for _, m := range missing {
		if h.Get(m.Header) == "" {
			out = append(out, Finding{m.Type, rawURL, status, "info", m.Note})
		}
	}

	if csp := h.Get("Content-Security-Policy"); csp != "" {
		lcsp := strings.ToLower(csp)
		if strings.Contains(lcsp, "unsafe-inline") || strings.Contains(lcsp, "unsafe-eval") {
			out = append(out, Finding{"weak_csp", rawURL, status, "low", "CSP içinde unsafe-inline/unsafe-eval görüldü; manuel değerlendir"})
		}
	}

	return out
}

func FormatFinding(f Finding) string {
	return fmt.Sprintf("%s | %d | %s | %s | %s", f.URL, f.Status, f.Type, f.Confidence, f.Note)
}
