package aianalysis

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/redact"
)

type Item struct {
	Title         string   `json:"title"`
	Asset         string   `json:"asset,omitempty"`
	Category      string   `json:"category"`
	Priority      string   `json:"priority"`
	Confidence    string   `json:"confidence"`
	Evidence      []string `json:"evidence,omitempty"`
	Impact        string   `json:"impact,omitempty"`
	WhyItMatters  string   `json:"why_it_matters"`
	NextStep      string   `json:"next_step,omitempty"`
	NextSteps     []string `json:"next_steps"`
	Reportability string   `json:"reportability,omitempty"`
}

type Output struct {
	GeneratedAt string   `json:"generated_at"`
	Summary     string   `json:"summary"`
	Items       []Item   `json:"items"`
	Warnings    []string `json:"warnings,omitempty"`
}

func SystemPrompt() string {
	return `Analyze authorized bug bounty recon output and return structured JSON only.
Schema: {"summary":"...","items":[{"title":"...","asset":"...","category":"api|idor|secret|headers|takeover|exposure|other","priority":"critical|high|medium|low|info","confidence":"high|medium|low","evidence":["..."],"impact":"...","why_it_matters":"...","next_step":"...","next_steps":["..."],"reportability":"likely_reportable|needs_manual_validation|low_signal|not_reportable"}],"warnings":["..."]}.
Do not provide exploitation instructions. Focus on safe verification, bounty impact, false-positive risk and manual review guidance.
Treat ordinary login pages, dashboard routes that only redirect or require login, robots.txt, sitemap.xml, 403 directory responses, and missing best-practice headers as low_signal or not_reportable unless the report includes concrete sensitive data exposure, authorization bypass, account takeover impact, or reproducible business impact.
For IDOR/BOLA replay output, prioritize possible_idor only when account B received a successful response for account A's owned-account request and the evidence includes object hints or sensitive-looking fields. Mark protected and public_endpoint as not_reportable or low_signal.
Do not suggest brute force, denial of service, spam, social engineering, credential attacks, destructive testing, or production automation.
Use likely_reportable only when the recon evidence already indicates concrete security impact, not merely an exposed route or authentication surface.`
}

func Local(report string) Output {
	out := Output{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Summary:     "Local structured analysis generated from recon keywords.",
	}
	lines := strings.Split(report, "\n")
	seen := map[string]bool{}
	probedAssets := collectLocalProbeAssets(lines)
	suppressed := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		trimmed = redact.String(trimmed)
		l := strings.ToLower(trimmed)
		asset := firstAsset(trimmed)
		if suppressLocalNoise(l, asset, probedAssets) {
			suppressed++
			continue
		}
		if localIDORSignal(l) {
			priority := "high"
			confidence := "low"
			reportability := "needs_manual_validation"
			impact := "Object identifiers and tenant/account routes can indicate authorization review opportunities."
			if strings.Contains(l, "possible_idor") {
				confidence = "medium"
				impact = "Account B received a successful response for an account A owned-resource request."
				if !strings.Contains(l, "fields:-") {
					confidence = "high"
					reportability = "likely_reportable"
					impact = "Potential cross-account access to sensitive or account-specific data."
				}
			}
			appendLocalItem(&out, seen, Item{
				Title:        "Authorization boundary review candidate",
				Asset:        asset,
				Category:     "idor",
				Priority:     priority,
				Confidence:   confidence,
				Evidence:     []string{trimmed},
				Impact:       impact,
				WhyItMatters: impact,
				NextStep:     "Reproduce with two owned accounts and capture minimal non-sensitive evidence.",
				NextSteps: []string{
					"Confirm both accounts are owned and allowed by program rules",
					"Verify account B can access account A-owned object without modifying data",
					"Prepare minimal reproduction steps and avoid retaining personal data",
				},
				Reportability: reportability,
			})
		} else if localSecretSignal(l) {
			appendLocalItem(&out, seen, Item{
				Title:        "Potential secret exposure candidate",
				Asset:        asset,
				Category:     "secret",
				Priority:     "high",
				Confidence:   "medium",
				Evidence:     []string{trimmed},
				Impact:       "Exposed credentials may allow unauthorized access if valid.",
				WhyItMatters: "Exposed credentials may allow unauthorized access if valid.",
				NextStep:     "Verify the finding manually without using the credential.",
				NextSteps: []string{
					"Verify the finding manually without using the credential",
					"Check whether the value is test, expired or production",
					"Prepare responsible disclosure evidence",
				},
				Reportability: "needs_manual_validation",
			})
		} else if localPublicAPISignal(l) {
			priority := "medium"
			confidence := "medium"
			reportability := "needs_manual_validation"
			impact := "Unauthenticated JSON/API response may expose business data or reveal authorization test cases."
			if strings.Contains(l, "fields:") || strings.Contains(l, "sensitive_fields") ||
				strings.Contains(l, "risk:high") || strings.Contains(l, "risk_score:") {
				priority = "high"
				confidence = "high"
				reportability = "likely_reportable"
				impact = "Unauthenticated API response appears to expose sensitive-looking fields."
			}
			appendLocalItem(&out, seen, Item{
				Title:        "Public API data exposure candidate",
				Asset:        asset,
				Category:     "api",
				Priority:     priority,
				Confidence:   confidence,
				Evidence:     []string{trimmed},
				Impact:       impact,
				WhyItMatters: impact,
				NextStep:     "Inspect the response shape and verify whether returned data should be public.",
				NextSteps: []string{
					"Confirm the endpoint is intended to be public",
					"Look for PII, financial data, roles, tokens or account identifiers",
					"Do not retain third-party personal data; capture minimal safe evidence",
				},
				Reportability: reportability,
			})
		} else if localAPIDocSignal(l) {
			appendLocalItem(&out, seen, Item{
				Title:        "API documentation review candidate",
				Asset:        asset,
				Category:     "api",
				Priority:     "low",
				Confidence:   "medium",
				Evidence:     []string{trimmed},
				Impact:       "API documentation is useful for mapping, but needs exposed sensitive operations to become reportable.",
				WhyItMatters: "API documentation is useful for mapping, but needs exposed sensitive operations to become reportable.",
				NextStep:     "Use it to guide authorized manual testing rather than reporting it alone.",
				NextSteps: []string{
					"Map authentication requirements",
					"Identify object identifiers and role boundaries",
					"Report only concrete data exposure or authorization bypass",
				},
				Reportability: "low_signal",
			})
		} else if strings.Contains(l, "header") || strings.Contains(l, "cors") || strings.Contains(l, "cookie") {
			appendLocalItem(&out, seen, Item{
				Title:        "Browser security configuration candidate",
				Asset:        asset,
				Category:     "headers",
				Priority:     "low",
				Confidence:   "medium",
				Evidence:     []string{trimmed},
				Impact:       "Header and cookie weaknesses can increase impact when combined with other issues.",
				WhyItMatters: "Header and cookie weaknesses can increase impact when combined with other issues.",
				NextStep:     "Confirm behavior in a browser and require concrete impact before reporting.",
				NextSteps: []string{
					"Confirm behavior in browser",
					"Check whether sensitive data is exposed",
					"Treat missing headers as low priority unless impact is demonstrated",
				},
				Reportability: "low_signal",
			})
		}
	}
	if suppressed > 0 {
		out.Warnings = append(out.Warnings, "Suppressed low-signal duplicate/noisy local findings: "+itoa(suppressed))
	}
	if len(out.Items) == 0 {
		out.Warnings = append(out.Warnings, "No high-signal lines were found by local analysis.")
	}
	return out
}

func localIDORSignal(line string) bool {
	return strings.Contains(line, "possible_idor") ||
		strings.Contains(line, "idor") ||
		strings.Contains(line, "bola") ||
		strings.Contains(line, "tenant") ||
		strings.Contains(line, "account_id") ||
		strings.Contains(line, "accountid") ||
		strings.Contains(line, "/account/") ||
		strings.Contains(line, "/accounts/")
}

func ToJSON(out Output) string {
	raw, _ := json.MarshalIndent(out, "", "  ")
	return string(raw)
}

func firstAsset(line string) string {
	line = strings.ReplaceAll(line, "%5BREDACTED%5D", "REDACTED")
	fields := strings.Fields(line)
	for _, field := range fields {
		cleaned := strings.Trim(field, "`[](),.;")
		cleaned = strings.ReplaceAll(cleaned, "[REDACTED]", "REDACTED")
		cleaned = strings.TrimSuffix(cleaned, "%60")
		if strings.HasPrefix(cleaned, "http://") || strings.HasPrefix(cleaned, "https://") {
			return cleaned
		}
		if strings.HasPrefix(cleaned, "/") {
			return cleaned
		}
		if strings.Contains(cleaned, ".") && !strings.Contains(cleaned, "=") {
			return cleaned
		}
	}
	return ""
}

func localSecretSignal(line string) bool {
	if strings.Contains(line, "secret") || strings.Contains(line, "token") ||
		strings.Contains(line, "private key") || strings.Contains(line, "private_key") ||
		strings.Contains(line, "api key") || strings.Contains(line, "apikey") ||
		strings.Contains(line, "possible_") {
		return true
	}
	return false
}

func localPublicAPISignal(line string) bool {
	return strings.Contains(line, "public_api_json") ||
		strings.Contains(line, "public_json") ||
		strings.Contains(line, "unauthenticated json response")
}

func localAPIDocSignal(line string) bool {
	return strings.Contains(line, "swagger") ||
		strings.Contains(line, "openapi") ||
		strings.Contains(line, "api-docs") ||
		strings.Contains(line, "graphql")
}

func suppressLocalNoise(line, asset string, probedAssets map[string]bool) bool {
	if strings.Contains(line, "auth_required_api") ||
		strings.Contains(line, "`auth_required`") ||
		strings.Contains(line, "authentication required") {
		return true
	}
	if strings.Contains(line, "api_endpoint / medium") && probedAssets[canonicalLocalAsset(asset)] {
		return true
	}
	if strings.Contains(line, "interesting_path") &&
		(strings.Contains(line, "/accounting") || strings.Contains(line, "public_html")) {
		return true
	}
	return false
}

func collectLocalProbeAssets(lines []string) map[string]bool {
	out := map[string]bool{}
	for _, line := range lines {
		l := strings.ToLower(line)
		if !strings.Contains(l, "get:") && !strings.Contains(l, "public_json") && !strings.Contains(l, "auth_required") {
			continue
		}
		asset := firstAsset(redact.String(strings.TrimSpace(line)))
		if asset == "" {
			continue
		}
		out[canonicalLocalAsset(asset)] = true
	}
	return out
}

func appendLocalItem(out *Output, seen map[string]bool, item Item) {
	key := item.Category + "|" + item.Title + "|" + canonicalLocalAsset(item.Asset)
	if key == "" || seen[key] {
		return
	}
	seen[key] = true
	out.Items = append(out.Items, item)
}

func canonicalLocalAsset(asset string) string {
	asset = strings.TrimSpace(asset)
	asset = strings.TrimSuffix(asset, "%60")
	if asset == "" {
		return ""
	}
	if strings.HasPrefix(asset, "http://") || strings.HasPrefix(asset, "https://") {
		for _, marker := range []string{"://"} {
			if idx := strings.Index(asset, marker); idx >= 0 {
				rest := asset[idx+len(marker):]
				if slash := strings.Index(rest, "/"); slash >= 0 {
					asset = rest[slash:]
				}
			}
		}
	}
	return strings.ToLower(strings.TrimRight(asset, "/"))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := [20]byte{}
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
