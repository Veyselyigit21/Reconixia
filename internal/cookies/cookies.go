package cookies

import (
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

// AnalyzeURL performs passive Set-Cookie security checks.
// It does not authenticate or mutate state; it only evaluates response cookie attributes.
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
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var out []Finding
	for _, c := range resp.Cookies() {
		name := c.Name
		lowerName := strings.ToLower(name)
		looksSession := strings.Contains(lowerName, "session") || strings.Contains(lowerName, "sid") || strings.Contains(lowerName, "token") || strings.Contains(lowerName, "auth") || strings.Contains(lowerName, "jwt")
		confidence := "info"
		if looksSession {
			confidence = "medium"
		}
		if !c.Secure {
			out = append(out, Finding{"cookie_missing_secure", rawURL, resp.StatusCode, confidence, "Cookie '" + name + "' Secure flag olmadan set ediliyor"})
		}
		if !c.HttpOnly {
			out = append(out, Finding{"cookie_missing_httponly", rawURL, resp.StatusCode, confidence, "Cookie '" + name + "' HttpOnly flag olmadan set ediliyor"})
		}
		if c.SameSite == http.SameSiteDefaultMode || c.SameSite == 0 {
			out = append(out, Finding{"cookie_missing_samesite", rawURL, resp.StatusCode, confidence, "Cookie '" + name + "' SameSite attribute olmadan set ediliyor"})
		}
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			out = append(out, Finding{"cookie_samesite_none_without_secure", rawURL, resp.StatusCode, "medium", "Cookie '" + name + "' SameSite=None fakat Secure yok"})
		}
	}
	return out
}
