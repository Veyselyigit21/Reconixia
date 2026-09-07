package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

func TestAnalyzeSpecsFlagsPossibleIDOR(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"userId":"acct_a","email":"owner@example.com","balance":1200}`))
	}))
	defer srv.Close()

	results, warnings := analyzeSpecs(context.Background(), safety.SafeHTTPClient(2*time.Second), []RequestSpec{{
		Method: http.MethodGet,
		URL:    srv.URL + "/api/users/123e4567-e89b-12d3-a456-426614174000",
	}}, analyzeOptions{
		authA:          "Authorization: Bearer account-a",
		authB:          "Authorization: Bearer account-b",
		rate:           100,
		maxRequests:    10,
		unauthBaseline: true,
	})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Classification != "possible_idor" {
		t.Fatalf("classification = %q", results[0].Classification)
	}
	if results[0].Risk != "high" {
		t.Fatalf("risk = %q", results[0].Risk)
	}
	if len(results[0].SensitiveFields) == 0 {
		t.Fatalf("expected sensitive fields: %#v", results[0])
	}
}

func TestAnalyzeSpecsMarksProtected(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer account-a":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"userId":"acct_a","email":"owner@example.com"}`))
		case "Bearer account-b":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	results, _ := analyzeSpecs(context.Background(), safety.SafeHTTPClient(2*time.Second), []RequestSpec{{
		Method: http.MethodGet,
		URL:    srv.URL + "/api/users/acct_a",
	}}, analyzeOptions{
		authA:          "Authorization: Bearer account-a",
		authB:          "Authorization: Bearer account-b",
		rate:           100,
		maxRequests:    10,
		unauthBaseline: true,
	})
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Classification != "protected" {
		t.Fatalf("classification = %q", results[0].Classification)
	}
}

func TestLoadHARSkipsCapturedAuth(t *testing.T) {
	tmp := t.TempDir() + "/capture.har"
	har := `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/api/users/1","headers":[{"name":"Authorization","value":"Bearer old"},{"name":"Accept","value":"application/json"}]}}]}}`
	if err := osWriteFile(tmp, har); err != nil {
		t.Fatal(err)
	}
	specs, err := loadHAR(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("specs = %d", len(specs))
	}
	if _, ok := specs[0].Headers["Authorization"]; ok {
		t.Fatalf("captured authorization header was not stripped")
	}
	if specs[0].Headers["Accept"] != "application/json" {
		t.Fatalf("accept header missing: %#v", specs[0].Headers)
	}
}

func TestProgramPolicyBlocksConfiguredURLs(t *testing.T) {
	t.Setenv("RECONIXIA_LAB_MODE", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	results, warnings := analyzeSpecs(context.Background(), safety.SafeHTTPClient(2*time.Second), []RequestSpec{{
		Method: http.MethodGet,
		URL:    srv.URL + "/checkout/pay",
	}}, analyzeOptions{
		authA: "Authorization: Bearer account-a",
		authB: "Authorization: Bearer account-b",
		rate:  100,
		policy: ProgramPolicy{
			AllowedMethods:     []string{http.MethodGet},
			BlockedURLKeywords: []string{"/checkout"},
		},
	})
	if len(results) != 0 {
		t.Fatalf("results = %#v", results)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "blocked by program policy") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestMethodPolicyStillRequiresMutatingOptIn(t *testing.T) {
	if methodAllowedByPolicy(http.MethodPost, false, []string{http.MethodPost}) {
		t.Fatal("POST in policy should still require mutating opt-in")
	}
	if !methodAllowedByPolicy(http.MethodPost, true, []string{http.MethodPost}) {
		t.Fatal("POST should be allowed when policy and mutating opt-in agree")
	}
	if methodAllowedByPolicy(http.MethodDelete, true, []string{http.MethodGet}) {
		t.Fatal("DELETE should be blocked when not in allowed methods")
	}
}

func TestReadOnlyGraphQLPostAllowedWithoutMutatingOptIn(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=SellerHubInventory",
		Body:   `{"operationName":"SellerHubInventory","query":"query SellerHubInventory { me { id } }","variables":{}}`,
	}
	if !requestAllowedByPolicy(spec, false, []string{http.MethodGet, http.MethodPost}) {
		t.Fatal("read-only GraphQL query POST should be allowed without mutating opt-in")
	}
}

func TestGraphQLMutationStillRequiresMutatingOptIn(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=UpdateProfile",
		Body:   `{"operationName":"UpdateProfile","query":"mutation UpdateProfile { updateProfile { id } }","variables":{}}`,
	}
	if requestAllowedByPolicy(spec, false, []string{http.MethodGet, http.MethodPost}) {
		t.Fatal("GraphQL mutation should still require mutating opt-in")
	}
}

func TestReadOnlyGraphQLPostGetsUnauthBaseline(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=SellerHubInventory",
		Body:   `{"operationName":"SellerHubInventory","query":"query SellerHubInventory { me { id } }","variables":{}}`,
	}
	if !canUnauthBaseline(spec) {
		t.Fatal("read-only GraphQL POST should get unauth baseline")
	}
}

func TestClassifyGraphQLDeniedAsProtected(t *testing.T) {
	spec := RequestSpec{Method: http.MethodPost, URL: "https://www.whatnot.com/services/graphql/"}
	result := classify(spec,
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-a","email":"a@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"errors":[{"message":"Not authorized"}]}`), Size: 41},
		responseSample{},
	)
	if result.Classification != "protected" {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestClassifyGraphQLUnauthDeniedNotPublicEndpoint(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=OrderDetail",
		Body:   `{"operationName":"OrderDetail","query":"query OrderDetail($orderId: ID!) { order(id: $orderId) { id email } }","variables":{"orderId":"123e4567-e89b-12d3-a456-426614174000"}}`,
	}
	result := classify(spec,
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-a","email":"a@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-a","email":"a@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"errors":[{"message":"Authentication required"}]}`), Size: 49},
	)
	if result.Classification != "possible_idor" {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestClassifyGraphQLMeQueryIsAccountScoped(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=Viewer",
		Body:   `{"operationName":"Viewer","query":"query Viewer { me { id email } }","variables":{}}`,
	}
	result := classify(spec,
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-a","email":"a@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-b","email":"b@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"errors":[{"message":"Authentication required"}]}`), Size: 49},
	)
	if result.Classification != "account_scoped" {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestClassifyGraphQLSameResponseWithoutObjectIDIsLowConfidence(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=Viewer",
		Body:   `{"operationName":"Viewer","query":"query Viewer { me { id email } }","variables":{}}`,
	}
	result := classify(spec,
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-a","email":"a@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":{"id":"account-a","email":"a@example.com"}}}`), Size: 58},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"errors":[{"message":"Authentication required"}]}`), Size: 49},
	)
	if result.Classification != "same_authenticated_response" {
		t.Fatalf("classification = %q", result.Classification)
	}
	if result.Confidence != "low" {
		t.Fatalf("confidence = %q", result.Confidence)
	}
}

func TestClassifyGraphQLEmptyAccountData(t *testing.T) {
	spec := RequestSpec{Method: http.MethodPost, URL: "https://www.whatnot.com/services/graphql/"}
	result := classify(spec,
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":null}}`), Size: 20},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":null}}`), Size: 20},
		responseSample{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"me":null}}`), Size: 20},
	)
	if result.Classification != "empty_or_anonymous" {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestGraphQLMutationDoesNotGetUnauthBaseline(t *testing.T) {
	spec := RequestSpec{
		Method: http.MethodPost,
		URL:    "https://www.whatnot.com/services/graphql/?operationName=UpdateProfile",
		Body:   `{"operationName":"UpdateProfile","query":"mutation UpdateProfile { updateProfile { id } }","variables":{}}`,
	}
	if canUnauthBaseline(spec) {
		t.Fatal("GraphQL mutation should not get unauth baseline")
	}
}

func TestLoadProgramPolicy(t *testing.T) {
	tmp := t.TempDir() + "/policy.json"
	body := `{
	  "name": "Whatnot owned-account IDOR",
	  "target": "whatnot.com",
	  "research_header": "X-HackerOne-Research",
	  "h1_user": "aello",
	  "rate": 2,
	  "max_requests": 25,
	  "allowed_methods": ["get", "HEAD", "get"],
	  "blocked_url_keywords": ["/checkout", "/bid", "/checkout"]
	}`
	if err := osWriteFile(tmp, body); err != nil {
		t.Fatal(err)
	}
	policy, err := loadProgramPolicy(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Target != "whatnot.com" || policy.H1User != "aello" {
		t.Fatalf("policy = %#v", policy)
	}
	if got := strings.Join(policy.AllowedMethods, ","); got != "GET,HEAD" {
		t.Fatalf("allowed methods = %q", got)
	}
	if got := strings.Join(policy.BlockedURLKeywords, ","); got != "/bid,/checkout" {
		t.Fatalf("blocked keywords = %q", got)
	}
}

func TestMethodAllowedDefaultsReadOnly(t *testing.T) {
	if methodAllowed(http.MethodPost, false) {
		t.Fatal("POST should require -allow-mutating")
	}
	if !methodAllowed(http.MethodGet, false) {
		t.Fatal("GET should be allowed")
	}
}

func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(strings.TrimSpace(content)), 0600)
}
