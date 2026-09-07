package researchheaders

import (
	"net/http"
	"os"
	"testing"
)

func TestApplyAddsHackerOneHeader(t *testing.T) {
	t.Setenv("RECONIXIA_H1_USERNAME", "h1-user")
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	Apply(req)
	if got := req.Header.Get(defaultHeaderName); got != "h1-user" {
		t.Fatalf("header = %q, want h1-user", got)
	}
	if got := req.Header.Get("User-Agent"); got != defaultUserAgent {
		t.Fatalf("user-agent = %q", got)
	}
}

func TestApplySupportsCustomHeader(t *testing.T) {
	t.Setenv("RECONIXIA_RESEARCH_HEADER_NAME", "X-Custom-Research")
	t.Setenv("RECONIXIA_RESEARCH_HEADER_VALUE", "custom-value")
	_ = os.Unsetenv("RECONIXIA_H1_USERNAME")
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	Apply(req)
	if got := req.Header.Get("X-Custom-Research"); got != "custom-value" {
		t.Fatalf("custom header = %q", got)
	}
}
