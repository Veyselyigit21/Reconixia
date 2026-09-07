package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLooksLikeSoft404MatchesWebflowNotFound(t *testing.T) {
	baseline := responseSample{
		Status:      200,
		ContentType: "text/html; charset=utf-8",
		Title:       "Not Found",
		Body:        `<html><head><title>Not Found</title><link href="https://www.syfe.com/404" rel="canonical"/></head></html>`,
	}
	candidate := responseSample{
		Status:      200,
		ContentType: "text/html; charset=utf-8",
		Title:       "Not Found",
		Body:        `<html><head><title>Not Found</title><link href="https://www.syfe.com/404" rel="canonical"/></head></html>`,
	}
	if !looksLikeSoft404(candidate, baseline) {
		t.Fatal("expected matching 200 Not Found HTML to be treated as soft-404")
	}
}

func TestLooksLikeSoft404DoesNotDropRealJSON(t *testing.T) {
	baseline := responseSample{
		Status:      200,
		ContentType: "text/html; charset=utf-8",
		Title:       "Not Found",
		Body:        `<html><head><title>Not Found</title></head></html>`,
	}
	candidate := responseSample{
		Status:      200,
		ContentType: "application/json",
		Body:        `{"openapi":"3.0.0"}`,
	}
	if looksLikeSoft404(candidate, baseline) {
		t.Fatal("expected real JSON response to survive soft-404 filter")
	}
}

func TestPageTitleNormalizesWhitespaceAndEntities(t *testing.T) {
	got := pageTitle("<html><title> API &amp; Docs \n Portal </title></html>")
	if got != "API & Docs Portal" {
		t.Fatalf("unexpected title: %q", got)
	}
}

func TestNormalizeSeedURLAllowsLocalhostPortInLabMode(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")
	got, err := normalizeSeedURL("http://localhost:3000/login", []string{"localhost"})
	if err != nil {
		t.Fatalf("normalizeSeedURL failed: %v", err)
	}
	if got != "http://localhost:3000" {
		t.Fatalf("seed URL = %q", got)
	}
}

func TestNormalizeSeedURLRejectsLocalhostWithoutLabMode(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "")
	if got, err := normalizeSeedURL("http://localhost:3000", []string{"localhost"}); err == nil {
		t.Fatalf("normalizeSeedURL = %q, want rejection", got)
	}
}

func TestNucleiTemplatesDirUsesEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NUCLEI_TEMPLATES", dir)
	t.Setenv("NUCLEI_TEMPLATES_PATH", "")
	if got := nucleiTemplatesDir(); got != dir {
		t.Fatalf("nucleiTemplatesDir = %q, want %q", got, dir)
	}
}

func TestProbeEndpointsClassifiesPublicJSON(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET,OPTIONS")
			w.Header().Set("Access-Control-Allow-Origin", "http://example.test")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	probes := probeEndpoints(context.Background(), []string{srv.URL}, []string{"/api/Products"}, Profile{Name: "test", Rate: 50, Threads: 2}, []string{"127.0.0.1"}, http.DefaultClient)
	if len(probes) != 1 {
		t.Fatalf("probes = %d, want 1: %#v", len(probes), probes)
	}
	if probes[0].Classification != "public_json" {
		t.Fatalf("classification = %q", probes[0].Classification)
	}
	if probes[0].GETStatus != 200 || probes[0].OPTIONSStatus != 204 {
		t.Fatalf("unexpected statuses: %#v", probes[0])
	}
	if !strings.Contains(probes[0].ContentType, "application/json") {
		t.Fatalf("content type = %q", probes[0].ContentType)
	}
}

func TestProbeEndpointsScoresSensitiveJSONFields(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"userId":"u_1","email":"aello@example.com","role":"admin","balance":1200,"access_token":"redacted"}`))
	}))
	defer srv.Close()

	probes := probeEndpoints(context.Background(), []string{srv.URL}, []string{"/api/me"}, Profile{Name: "test", Rate: 50, Threads: 2}, []string{"127.0.0.1"}, http.DefaultClient)
	if len(probes) != 1 {
		t.Fatalf("probes = %d, want 1: %#v", len(probes), probes)
	}
	if probes[0].Classification != "public_json_sensitive" {
		t.Fatalf("classification = %q", probes[0].Classification)
	}
	if probes[0].RiskScore == 0 || probes[0].Risk == "" {
		t.Fatalf("expected sensitive risk, got %#v", probes[0])
	}
	if len(probes[0].SensitiveFields) < 4 {
		t.Fatalf("sensitive fields = %#v", probes[0].SensitiveFields)
	}
}

func TestSensitiveFieldClassifierFallsBackForTruncatedJSON(t *testing.T) {
	fields := classifySensitiveFields([]byte(`{"items":[{"accountId":"a1","balance":1200}`), "application/json")
	if len(fields) < 2 {
		t.Fatalf("fields = %#v, want accountId and balance from raw key fallback", fields)
	}
	score, risk := sensitiveFieldRisk(fields)
	if score == 0 || risk == "" {
		t.Fatalf("risk = %q/%d", risk, score)
	}
}

func TestEndpointProbeFindingsPromotesPublicJSON(t *testing.T) {
	findings := endpointProbeFindings([]EndpointProbe{{
		URL:            "https://example.com/api/products",
		GETStatus:      200,
		Classification: "public_json",
	}})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Type != "public_api_json" {
		t.Fatalf("type = %q", findings[0].Type)
	}
}

func TestEndpointProbeFindingsPromotesSensitiveJSON(t *testing.T) {
	findings := endpointProbeFindings([]EndpointProbe{{
		URL:            "https://example.com/api/me",
		GETStatus:      200,
		Classification: "public_json_sensitive",
		RiskScore:      85,
		Risk:           "high",
		SensitiveFields: []SensitiveField{
			{Path: "$.access_token", Category: "auth_secret", Severity: "high"},
			{Path: "$.email", Category: "pii", Severity: "medium"},
		},
	}})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Type != "public_api_sensitive_fields" {
		t.Fatalf("type = %q", findings[0].Type)
	}
	if findings[0].Confidence != "high" {
		t.Fatalf("confidence = %q", findings[0].Confidence)
	}
}
