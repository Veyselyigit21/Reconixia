package researchheaders

import (
	"net/http"
	"os"
	"strings"
)

const (
	defaultUserAgent  = "Reconixia/1.0 AuthorizedResearch"
	defaultHeaderName = "X-HackerOne-Research"
)

// Apply adds Reconixia's default user agent and optional researcher attribution headers.
// Programs often ask researchers to identify production traffic. The default header name
// follows HackerOne's common convention and can be overridden for translated/custom rules.
func Apply(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}
	name := strings.TrimSpace(os.Getenv("RECONIXIA_RESEARCH_HEADER_NAME"))
	value := strings.TrimSpace(os.Getenv("RECONIXIA_RESEARCH_HEADER_VALUE"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("RECONIXIA_H1_USERNAME"))
	}
	if name == "" {
		name = defaultHeaderName
	}
	if value != "" {
		req.Header.Set(name, value)
	}
}
