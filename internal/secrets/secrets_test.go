package secrets

import "testing"

func TestScanDetectsHighSignalSecret(t *testing.T) {
	body := `const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";`
	got := Scan(body)
	if len(got) == 0 {
		t.Fatal("expected GitHub token-like finding")
	}
	if got[0].Note == "" {
		t.Fatal("expected note")
	}
}

func TestScanSkipsDummyGenericSecret(t *testing.T) {
	body := `api_key = "placeholder_placeholder_placeholder"`
	got := Scan(body)
	if len(got) != 0 {
		t.Fatalf("expected dummy secret to be skipped, got %#v", got)
	}
}
