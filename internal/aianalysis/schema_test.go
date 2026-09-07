package aianalysis

import (
	"encoding/json"
	"testing"
)

func TestLocalAnalysisProducesStructuredOutput(t *testing.T) {
	out := Local("- https://example.com/api/v1/users\n- possible_openai_key in app.js")
	if len(out.Items) == 0 {
		t.Fatalf("expected structured items")
	}
	raw := ToJSON(out)
	var parsed Output
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed.GeneratedAt == "" {
		t.Fatalf("generated_at empty")
	}
}

func TestLocalAnalysisKeepsRelativeAPIAssets(t *testing.T) {
	out := Local("- `/api/Users` [200] public_api_json / medium - unauthenticated JSON response")
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(out.Items))
	}
	if out.Items[0].Asset != "/api/Users" {
		t.Fatalf("asset = %q", out.Items[0].Asset)
	}
}

func TestLocalAnalysisDoesNotTreatRedactedQueryKeyAsSecret(t *testing.T) {
	out := Local("- `/api/Challenges/?key=%5BREDACTED%5D` [200] public_api_json / medium - unauthenticated JSON response")
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(out.Items))
	}
	if out.Items[0].Asset != "/api/Challenges/?key=REDACTED" {
		t.Fatalf("asset = %q", out.Items[0].Asset)
	}
	for _, item := range out.Items {
		if item.Category == "secret" {
			t.Fatalf("redacted query key was treated as secret: %#v", item)
		}
	}
}

func TestLocalAnalysisSuppressesEndpointDiscoveryDuplicates(t *testing.T) {
	report := `## Endpoint Probes
- ` + "`http://localhost:3000/api/Users` GET:401 HEAD:401 OPTIONS:204 `auth_required` 972 bytes - authentication required" + `
- ` + "`http://localhost:3000/api/Products` GET:200 HEAD:200 OPTIONS:204 `public_json` 13212 bytes - unauthenticated JSON response; review for sensitive data exposure" + `
## Findings
- ` + "`/api/Users` [0] api_endpoint / medium - API manuel inceleme adayı" + `
- ` + "`/api/Products` [0] api_endpoint / medium - API manuel inceleme adayı" + `
- ` + "`http://localhost:3000/api/Users` [401] auth_required_api / info - endpoint exists and requires authentication" + `
- ` + "`http://localhost:3000/api/Products` [200] public_api_json / medium - unauthenticated JSON response; review for data exposure or missing authorization" + `
`
	out := Local(report)
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1: %#v", len(out.Items), out.Items)
	}
	if out.Items[0].Asset != "http://localhost:3000/api/Products" {
		t.Fatalf("asset = %q", out.Items[0].Asset)
	}
	if out.Items[0].Title != "Public API data exposure candidate" {
		t.Fatalf("title = %q", out.Items[0].Title)
	}
	if len(out.Warnings) == 0 {
		t.Fatalf("expected suppression warning")
	}
}

func TestLocalAnalysisDoesNotFlagAccountingAsIDOR(t *testing.T) {
	out := Local("- `http://localhost:3000/accounting` GET:200 `public_html` - unauthenticated HTML response")
	if len(out.Items) != 0 {
		t.Fatalf("items = %d, want 0: %#v", len(out.Items), out.Items)
	}
}

func TestLocalAnalysisPrioritizesPossibleIDOR(t *testing.T) {
	out := Local("- **possible_idor** `high/high` A:200 B:200 unauth:401 `https://api.example.com/users/123` fields:pii:$.email hints:object_id_in_path")
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(out.Items))
	}
	item := out.Items[0]
	if item.Category != "idor" {
		t.Fatalf("category = %q", item.Category)
	}
	if item.Reportability != "likely_reportable" {
		t.Fatalf("reportability = %q", item.Reportability)
	}
	if item.Confidence != "high" {
		t.Fatalf("confidence = %q", item.Confidence)
	}
}
