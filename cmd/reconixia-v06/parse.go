package main

import (
	"regexp"
	"sort"
	"strings"
)

func firstURL(lines []string) []string {
	out := []string{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) > 0 && strings.HasPrefix(f[0], "http") {
			out = append(out, f[0])
		}
	}
	return uniq(out)
}

func uniq(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x == "" || m[x] {
			continue
		}
		m[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func extractJS(base, body string) []string {
	re := regexp.MustCompile(`(?i)(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)['"']`)
	out := []string{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, absURL(base, m[1]))
	}
	return out
}

func extractEndpoints(body string) []string {
	re := regexp.MustCompile(`(?i)["'\x60](/(?:api|v1|v2|v3|graphql|admin|user|account|org|tenant|auth|login)[^"'\x60\s<>]*)['"'\x60]`)
	out := []string{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func extractURLs(body string) []string {
	return regexp.MustCompile(`https?://[^\s"'<>]+`).FindAllString(body, -1)
}

func pageTitle(body string) string {
	m := regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`).FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.Join(strings.Fields(htmlEntityReplacer.Replace(m[1])), " ")
}

func absURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(ref, "//") {
		return "https:" + ref
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(ref, "/")
}

func classifyEndpoints(eps []string) []Finding {
	out := []Finding{}
	for _, e := range eps {
		l := strings.ToLower(e)
		if strings.Contains(l, "id=") || strings.Contains(l, "user_id") ||
			strings.Contains(l, "account_id") || strings.Contains(l, "tenant_id") ||
			strings.Contains(l, "org_id") || strings.Contains(l, "/users/") ||
			strings.Contains(l, "/accounts/") {
			out = append(out, Finding{"idor_candidate", e, 0, "medium", "IDOR/manual authorization review adayı"})
		} else if strings.Contains(l, "api") || strings.Contains(l, "graphql") {
			out = append(out, Finding{"api_endpoint", e, 0, "medium", "API manuel inceleme adayı"})
		}
	}
	return out
}

func classifyPath(p string) string {
	p = strings.ToLower(p)
	if strings.Contains(p, "swagger") || strings.Contains(p, "openapi") {
		return "api_documentation"
	}
	if strings.Contains(p, "api") || strings.Contains(p, "graphql") {
		return "api_surface"
	}
	if strings.Contains(p, "admin") || strings.Contains(p, "panel") ||
		strings.Contains(p, "dashboard") || strings.Contains(p, "login") {
		return "auth_or_admin_surface"
	}
	if strings.Contains(p, "config") || strings.Contains(p, "backup") ||
		strings.Contains(p, ".env") || strings.Contains(p, ".git") {
		return "information_disclosure_candidate"
	}
	return "interesting_path"
}

func confidence(c int) string {
	if c == 200 {
		return "high"
	}
	if c == 401 || c == 403 {
		return "medium"
	}
	return "low"
}

var htmlEntityReplacer = strings.NewReplacer(
	"&amp;", "&",
	"&lt;", "<",
	"&gt;", ">",
	"&quot;", `"`,
	"&#39;", "'",
)
