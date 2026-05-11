package aianalysis

import (
	"encoding/json"
	"sort"
	"strings"
)

type Finding struct {
	Category   string   `json:"category"`
	Priority   string   `json:"priority"`
	Evidence   []string `json:"evidence"`
	NextAction string   `json:"next_action"`
}

type Result struct {
	Summary  string    `json:"summary"`
	Findings []Finding `json:"findings"`
}

func Local(report string) Result {
	lines := strings.Split(report, "\n")
	buckets := map[string][]string{
		"api_surface": {},
		"idor_candidate": {},
		"information_disclosure": {},
		"auth_or_admin_surface": {},
		"cors_or_headers": {},
		"cookie_security": {},
		"takeover_surface": {},
		"secret_candidate": {},
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case containsAny(lower, "idor", "user_id", "account_id", "tenant_id", "org_id", "/users/", "/accounts/"):
			buckets["idor_candidate"] = appendLimited(buckets["idor_candidate"], trimmed)
		case containsAny(lower, "swagger", "openapi", "graphql", "api_endpoint", "api_surface", "/api", "api/"):
			buckets["api_surface"] = appendLimited(buckets["api_surface"], trimmed)
		case containsAny(lower, "secret", "apikey", "api key", "token", "aws", "github_token", "openai"):
			buckets["secret_candidate"] = appendLimited(buckets["secret_candidate"], trimmed)
		case containsAny(lower, "admin", "login", "dashboard", "panel", "auth"):
			buckets["auth_or_admin_surface"] = appendLimited(buckets["auth_or_admin_surface"], trimmed)
		case containsAny(lower, "cors", "missing_hsts", "missing_csp", "weak_csp", "x-frame", "referrer-policy"):
			buckets["cors_or_headers"] = appendLimited(buckets["cors_or_headers"], trimmed)
		case containsAny(lower, "cookie", "httponly", "samesite", "secure flag"):
			buckets["cookie_security"] = appendLimited(buckets["cookie_security"], trimmed)
		case containsAny(lower, "takeover", "cname", "dangling"):
			buckets["takeover_surface"] = appendLimited(buckets["takeover_surface"], trimmed)
		case containsAny(lower, "config", "backup", "debug", "env", "information_disclosure"):
			buckets["information_disclosure"] = appendLimited(buckets["information_disclosure"], trimmed)
		}
	}

	var findings []Finding
	order := []string{"secret_candidate", "idor_candidate", "api_surface", "information_disclosure", "auth_or_admin_surface", "takeover_surface", "cors_or_headers", "cookie_security"}
	for _, category := range order {
		evidence := uniq(buckets[category])
		if len(evidence) == 0 {
			continue
		}
		findings = append(findings, Finding{
			Category:   category,
			Priority:   priority(category),
			Evidence:   evidence,
			NextAction: nextAction(category),
		})
	}

	return Result{Summary: summary(findings), Findings: findings}
}

func ToJSON(result Result) string {
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return `{"summary":"json marshal error","findings":[]}`
	}
	return string(raw)
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func appendLimited(items []string, value string) []string {
	if len(items) >= 20 {
		return items
	}
	return append(items, value)
}

func uniq(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func priority(category string) string {
	switch category {
	case "secret_candidate", "idor_candidate":
		return "high"
	case "api_surface", "information_disclosure", "takeover_surface":
		return "medium"
	default:
		return "low"
	}
}

func nextAction(category string) string {
	switch category {
	case "secret_candidate":
		return "Verify exposure, confirm scope, and prepare responsible disclosure with redacted evidence."
	case "idor_candidate":
		return "Manually review authorization boundaries with owned/test accounts only."
	case "api_surface":
		return "Prioritize API documentation, GraphQL, and versioned endpoints for manual review."
	case "information_disclosure":
		return "Check whether the exposed resource contains sensitive data or environment details."
	case "auth_or_admin_surface":
		return "Review access control, login behavior, and exposed admin surfaces manually."
	case "takeover_surface":
		return "Confirm DNS/provider ownership state without claiming third-party resources."
	case "cors_or_headers":
		return "Validate impact on sensitive endpoints before reporting."
	case "cookie_security":
		return "Verify cookie flags on authenticated and unauthenticated responses."
	default:
		return "Manual review recommended."
	}
}

func summary(findings []Finding) string {
	if len(findings) == 0 {
		return "No prioritized items detected by local structured analysis."
	}
	return "Local structured analysis produced prioritized review categories from the Reconixia report."
}
