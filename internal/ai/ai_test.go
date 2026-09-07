package ai

import "testing"

func TestChunkReportRedactsAndSplits(t *testing.T) {
	chunks := ChunkReport("token=sk-test1234567890abcdef\nline2\nline3", 12)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	for _, chunk := range chunks {
		if len(chunk) > 32 {
			t.Fatalf("chunk unexpectedly large: %d", len(chunk))
		}
		if contains(chunk, "sk-test1234567890abcdef") {
			t.Fatalf("chunk contains unredacted secret: %q", chunk)
		}
	}
}

func TestParseOutputFromFencedJSON(t *testing.T) {
	out, err := ParseOutput("```json\n{\"summary\":\"ok\",\"items\":[{\"title\":\"API\",\"asset\":\"https://example.com/api\",\"category\":\"api\",\"priority\":\"medium\",\"confidence\":\"high\",\"impact\":\"review auth\",\"why_it_matters\":\"auth\",\"next_step\":\"manual review\",\"next_steps\":[\"manual review\"],\"reportability\":\"needs_manual_validation\"}]}\n```")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(out.Items))
	}
	if out.Items[0].Asset != "https://example.com/api" {
		t.Fatalf("asset = %q", out.Items[0].Asset)
	}
}

func TestParseOutputCleansAssetAndDowngradesRouteOnlyFindings(t *testing.T) {
	out, err := ParseOutput(`{"summary":"ok","items":[{"title":"Authentication Surface Detected","asset":"https://example.com/login%60","category":"other","priority":"high","confidence":"high","impact":"login exists","why_it_matters":"route exists","next_step":"Verify rate limiting","next_steps":["Try brute force"],"reportability":"likely_reportable"}]}`)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(out.Items))
	}
	item := out.Items[0]
	if item.Asset != "https://example.com/login" {
		t.Fatalf("asset = %q", item.Asset)
	}
	if item.Reportability != "needs_manual_validation" {
		t.Fatalf("reportability = %q", item.Reportability)
	}
	if item.Confidence != "medium" {
		t.Fatalf("confidence = %q", item.Confidence)
	}
	if contains(item.NextStep, "Verify rate limiting") {
		t.Fatalf("unsafe guidance was not sanitized: %q", item.NextStep)
	}
	if contains(item.NextSteps[0], "brute force") {
		t.Fatalf("unsafe next step was not sanitized: %q", item.NextSteps[0])
	}
}

func TestChatContentFallsBackToReasoning(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"content":"","reasoning":"{\"summary\":\"ok\",\"items\":[]}"}}]}`)
	content, err := chatContent(body)
	if err != nil {
		t.Fatalf("chatContent failed: %v", err)
	}
	if content != `{"summary":"ok","items":[]}` {
		t.Fatalf("content = %q", content)
	}
}

func TestCompactPreviewRedactsAndTruncates(t *testing.T) {
	preview := compactPreview("token=sk-test1234567890abcdef "+"abcdefghijklmnopqrstuvwxyz", 20)
	if contains(preview, "sk-test1234567890abcdef") {
		t.Fatalf("preview leaked secret: %q", preview)
	}
	if len(preview) > 23 {
		t.Fatalf("preview too long: %q", preview)
	}
}

func contains(s, needle string) bool {
	return len(needle) == 0 || (len(s) >= len(needle) && index(s, needle) >= 0)
}

func index(s, needle string) int {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
