package aianalysis

import (
	"encoding/json"
	"strings"
	"time"
)

type Item struct {
	Title      string   `json:"title"`
	Category   string   `json:"category"`
	Priority   string   `json:"priority"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
	WhyItMatters string `json:"why_it_matters"`
	NextSteps  []string `json:"next_steps"`
}

type Output struct {
	GeneratedAt string `json:"generated_at"`
	Summary     string `json:"summary"`
	Items       []Item `json:"items"`
	Warnings    []string `json:"warnings,omitempty"`
}

func SystemPrompt() string {
	return `Analyze authorized bug bounty recon output and return structured JSON only.
Schema: {"summary":"...","items":[{"title":"...","category":"api|idor|secret|headers|takeover|exposure|other","priority":"critical|high|medium|low|info","confidence":"high|medium|low","evidence":["..."],"why_it_matters":"...","next_steps":["..."]}],"warnings":["..."]}.
Do not provide exploitation instructions. Focus on safe verification, prioritization, false-positive risk and manual review guidance.`
}

func Local(report string) Output {
	out := Output{GeneratedAt: time.Now().Format(time.RFC3339), Summary: "Local structured analysis generated from recon keywords."}
	lines := strings.Split(report, "\n")
	for _, line := range lines {
		l := strings.ToLower(line)
		if strings.Contains(l, "secret") || strings.Contains(l, "key") || strings.Contains(l, "token") {
			out.Items = append(out.Items, Item{Title: "Potential secret exposure candidate", Category: "secret", Priority: "high", Confidence: "medium", Evidence: []string{strings.TrimSpace(line)}, WhyItMatters: "Exposed credentials may allow unauthorized access if valid.", NextSteps: []string{"Verify the finding manually without using the credential", "Check whether the value is test, expired or production", "Prepare responsible disclosure evidence"}})
		} else if strings.Contains(l, "api") || strings.Contains(l, "graphql") || strings.Contains(l, "swagger") || strings.Contains(l, "openapi") {
			out.Items = append(out.Items, Item{Title: "API surface review candidate", Category: "api", Priority: "medium", Confidence: "medium", Evidence: []string{strings.TrimSpace(line)}, WhyItMatters: "API surfaces often expose authorization and data access issues.", NextSteps: []string{"Review authentication boundaries", "Map roles and object identifiers", "Look for safe authorization test cases"}})
		} else if strings.Contains(l, "idor") || strings.Contains(l, "tenant") || strings.Contains(l, "account") {
			out.Items = append(out.Items, Item{Title: "Authorization review candidate", Category: "idor", Priority: "high", Confidence: "low", Evidence: []string{strings.TrimSpace(line)}, WhyItMatters: "Object identifiers and tenant/account routes can indicate authorization review opportunities.", NextSteps: []string{"Confirm the endpoint is in scope", "Use authorized test accounts only", "Check whether access controls are enforced"}})
		} else if strings.Contains(l, "header") || strings.Contains(l, "cors") || strings.Contains(l, "cookie") {
			out.Items = append(out.Items, Item{Title: "Browser security configuration candidate", Category: "headers", Priority: "low", Confidence: "medium", Evidence: []string{strings.TrimSpace(line)}, WhyItMatters: "Header and cookie weaknesses can increase impact when combined with other issues.", NextSteps: []string{"Confirm behavior in browser", "Check whether sensitive data is exposed", "Treat missing headers as low priority unless impact is demonstrated"}})
		}
	}
	if len(out.Items) == 0 { out.Warnings = append(out.Warnings, "No high-signal lines were found by local analysis.") }
	return out
}

func ToJSON(out Output) string {
	raw, _ := json.MarshalIndent(out, "", "  ")
	return string(raw)
}
