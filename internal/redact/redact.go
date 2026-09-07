package redact

import (
	"net/url"
	"regexp"
	"strings"
)

var valuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	regexp.MustCompile(`\bGOCSPX-[0-9A-Za-z_-]{20,}\b`),
	regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9_/.-]{20,}`),
	regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`),
	regexp.MustCompile(`\bkey-[0-9a-fA-F]{32}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
}

var assignmentPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|token|password|passwd|pwd)([\s:=]+)["']?[A-Za-z0-9_\-./+=]{16,}["']?`)

var sensitiveQueryKeys = map[string]bool{
	"access_token":  true,
	"api_key":       true,
	"apikey":        true,
	"auth_token":    true,
	"client_secret": true,
	"code":          true,
	"key":           true,
	"password":      true,
	"secret":        true,
	"sig":           true,
	"signature":     true,
	"token":         true,
}

func String(input string) string {
	out := redactURL(input)
	for _, re := range valuePatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	out = assignmentPattern.ReplaceAllString(out, "$1$2[REDACTED]")
	return out
}

func Strings(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, String(item))
	}
	return out
}

func redactURL(input string) string {
	trimmed := strings.TrimSpace(input)
	u, err := url.Parse(trimmed)
	if err != nil || u == nil {
		return redactEmbeddedURLs(input)
	}
	if u.Scheme == "" && u.Host == "" && u.RawQuery != "" {
		if !strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "?") {
			return redactEmbeddedURLs(input)
		}
		redactParsedURL(u)
		return u.String()
	}
	if u.Scheme == "" || u.Host == "" {
		return redactEmbeddedURLs(input)
	}
	redactParsedURL(u)
	return u.String()
}

func redactEmbeddedURLs(input string) string {
	re := regexp.MustCompile(`https?://[^\s"'<>]+`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		u, err := url.Parse(match)
		if err != nil || u == nil || u.Host == "" {
			return match
		}
		redactParsedURL(u)
		return u.String()
	})
}

func redactParsedURL(u *url.URL) {
	if u.User != nil {
		u.User = url.UserPassword("[REDACTED]", "[REDACTED]")
	}
	q := u.Query()
	for key := range q {
		if sensitiveQueryKeys[strings.ToLower(key)] {
			q.Set(key, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()
}
