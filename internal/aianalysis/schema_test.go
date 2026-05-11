package aianalysis

import (
	"encoding/json"
	"testing"
)

func TestLocalAnalysisProducesStructuredOutput(t *testing.T) {
	out := Local("- https://example.com/api/v1/users\n- possible_openai_key in app.js")
	if len(out.Items) == 0 { t.Fatalf("expected structured items") }
	raw := ToJSON(out)
	var parsed Output
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil { t.Fatalf("invalid json: %v", err) }
	if parsed.GeneratedAt == "" { t.Fatalf("generated_at empty") }
}
