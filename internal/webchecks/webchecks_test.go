package webchecks

import "testing"

func TestParamRiskCandidatesClassifies(t *testing.T) {
	urls := []string{
		"https://x.example.com/a?next=/home",             // open redirect
		"https://x.example.com/b?url=https://in.ternal",  // ssrf
		"https://x.example.com/c?file=../../etc/passwd",  // lfi
		"https://x.example.com/d?q=hello",                // nothing
		"https://x.example.com/a?next=/home",             // duplicate -> deduped
	}
	got := ParamRiskCandidates(urls)
	counts := map[string]int{}
	for _, f := range got {
		counts[f.Type]++
	}
	if counts["open_redirect_candidate"] != 1 {
		t.Errorf("open_redirect_candidate 1 bekleniyordu, %d", counts["open_redirect_candidate"])
	}
	if counts["ssrf_candidate"] != 1 {
		t.Errorf("ssrf_candidate 1 bekleniyordu, %d", counts["ssrf_candidate"])
	}
	if counts["lfi_candidate"] != 1 {
		t.Errorf("lfi_candidate 1 bekleniyordu, %d", counts["lfi_candidate"])
	}
}

func TestRedirectsTo(t *testing.T) {
	m := "reconixia-oredir.example"
	cases := map[string]bool{
		"https://reconixia-oredir.example/":      true,
		"//reconixia-oredir.example/path":        true,
		"https://legit.example.com/":             false,
		"/relative/only":                         false,
	}
	for loc, want := range cases {
		if got := redirectsTo(loc, m); got != want {
			t.Errorf("redirectsTo(%q)=%v, beklenen %v", loc, got, want)
		}
	}
}
