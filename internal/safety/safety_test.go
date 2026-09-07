package safety

import "testing"

func TestNormalizeTargetAcceptsDomainsAndURLs(t *testing.T) {
	cases := map[string]string{
		"example.com":              "example.com",
		"HTTPS://Sub.Example.COM":  "sub.example.com",
		"https://example.com/path": "example.com",
		"example.com:443":          "example.com",
	}

	for input, want := range cases {
		got, ok := NormalizeTarget(input)
		if !ok {
			t.Fatalf("NormalizeTarget(%q) was rejected", input)
		}
		if got != want {
			t.Fatalf("NormalizeTarget(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeTargetRejectsUnsafeInputs(t *testing.T) {
	cases := []string{
		"",
		"example.com;whoami",
		"example.com && id",
		"localhost",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254",
		"100.100.100.200",
		"http://127.0.0.1/admin",
	}

	for _, input := range cases {
		if got, ok := NormalizeTarget(input); ok {
			t.Fatalf("NormalizeTarget(%q) = %q, want rejection", input, got)
		}
	}
}

func TestLabModeAllowsLoopbackAndPrivateButNotMetadata(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")

	allowedTargets := []string{"localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1"}
	for _, input := range allowedTargets {
		if _, ok := NormalizeTarget(input); !ok {
			t.Fatalf("NormalizeTarget(%q) rejected in lab mode", input)
		}
	}

	allowedURLs := []string{"http://localhost:3000", "http://127.0.0.1:8080", "http://10.0.0.5"}
	for _, input := range allowedURLs {
		if !IsSafeFetchURL(input) {
			t.Fatalf("IsSafeFetchURL(%q) rejected in lab mode", input)
		}
	}

	blocked := []string{"169.254.169.254", "100.100.100.200", "http://169.254.169.254/latest/meta-data/"}
	for _, input := range blocked {
		if got, ok := NormalizeTarget(input); ok {
			t.Fatalf("NormalizeTarget(%q) = %q in lab mode, want rejection", input, got)
		}
		if IsSafeFetchURL(input) {
			t.Fatalf("IsSafeFetchURL(%q) allowed metadata target in lab mode", input)
		}
	}
}

func TestIsSafeFetchURL(t *testing.T) {
	allowed := []string{
		"https://example.com",
		"http://sub.example.com/path?q=1",
	}
	for _, input := range allowed {
		if !IsSafeFetchURL(input) {
			t.Fatalf("IsSafeFetchURL(%q) = false, want true", input)
		}
	}

	blocked := []string{
		"ftp://example.com/file",
		"https://127.0.0.1/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://10.0.0.1/",
		"not a url",
	}
	for _, input := range blocked {
		if IsSafeFetchURL(input) {
			t.Fatalf("IsSafeFetchURL(%q) = true, want false", input)
		}
	}
}

func TestScopeAllowsURL(t *testing.T) {
	rules := []string{"example.com", "*.example.com", "!admin.example.com"}

	allowed := []string{
		"https://example.com",
		"https://api.example.com/v1",
	}
	for _, input := range allowed {
		if !ScopeAllowsURL(input, rules) {
			t.Fatalf("ScopeAllowsURL(%q) = false, want true", input)
		}
	}

	blocked := []string{
		"https://admin.example.com",
		"https://evil.com",
		"http://127.0.0.1",
	}
	for _, input := range blocked {
		if ScopeAllowsURL(input, rules) {
			t.Fatalf("ScopeAllowsURL(%q) = true, want false", input)
		}
	}
}

func TestFilterSafeScopedURLsDeduplicatesAndFilters(t *testing.T) {
	input := []string{
		"https://example.com",
		"https://example.com",
		"https://api.example.com",
		"https://admin.example.com",
		"http://127.0.0.1",
		"https://evil.com",
	}
	rules := []string{"example.com", "*.example.com", "!admin.example.com"}

	got := FilterSafeScopedURLs(input, rules)
	want := []string{"https://example.com", "https://api.example.com"}
	if len(got) != len(want) {
		t.Fatalf("FilterSafeScopedURLs length = %d, want %d; got %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FilterSafeScopedURLs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
