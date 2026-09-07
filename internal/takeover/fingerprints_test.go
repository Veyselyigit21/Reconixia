package takeover

import "testing"

func TestDetectProvider(t *testing.T) {
	tests := []struct {
		name     string
		cname    string
		provider string
	}{
		{name: "github pages", cname: "project.github.io.", provider: "github_pages"},
		{name: "vercel", cname: "cname.vercel-dns.com.vercel.app", provider: "vercel"},
		{name: "netlify global cdn", cname: "example.netlifyglobalcdn.com", provider: "netlify"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, ok := DetectProvider(tt.cname)
			if !ok {
				t.Fatalf("expected provider for %q", tt.cname)
			}
			if fp.Provider != tt.provider {
				t.Fatalf("provider = %q, want %q", fp.Provider, tt.provider)
			}
		})
	}
}

func TestDetectProviderUnknown(t *testing.T) {
	if fp, ok := DetectProvider("example.com"); ok {
		t.Fatalf("unexpected provider: %#v", fp)
	}
}
