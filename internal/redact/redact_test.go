package redact

import (
	"strings"
	"testing"
)

func TestStringRedactsKnownSecrets(t *testing.T) {
	input := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"
	got := String(input)
	if strings.Contains(got, "sk-abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("secret was not redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("redaction marker missing: %q", got)
	}
}

func TestStringRedactsSensitiveQueryValues(t *testing.T) {
	input := "https://example.com/callback?token=abcdef1234567890&next=/home"
	got := String(input)
	if strings.Contains(got, "abcdef1234567890") {
		t.Fatalf("query token was not redacted: %q", got)
	}
	if !strings.Contains(got, "token=%5BREDACTED%5D") {
		t.Fatalf("redacted query value missing: %q", got)
	}
}

func TestStringRedactsRelativeSensitiveQueryValues(t *testing.T) {
	input := "/callback?access_token=abcdef1234567890&next=/home"
	got := String(input)
	if strings.Contains(got, "abcdef1234567890") {
		t.Fatalf("relative query token was not redacted: %q", got)
	}
}

func TestStringDoesNotURLencodeWholeReportLine(t *testing.T) {
	input := "- `/api/Challenges/?key=%5BREDACTED%5D` [0] api_endpoint / medium"
	got := String(input)
	if strings.Contains(got, "%60") || strings.Contains(got, "%5B0%5D") {
		t.Fatalf("report line was URL-encoded: %q", got)
	}
	if !strings.Contains(got, "/api/Challenges/") {
		t.Fatalf("report line path was lost: %q", got)
	}
}

func TestStringRedactsEmbeddedBasicAuthURL(t *testing.T) {
	input := "fetch https://user:pass@example.com/private"
	got := String(input)
	if strings.Contains(got, "user:pass") {
		t.Fatalf("basic auth was not redacted: %q", got)
	}
}
