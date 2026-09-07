package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const maxSensitiveFields = 32

var emailValuePattern = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
var jsonKeyPattern = regexp.MustCompile(`"((?:\\.|[^"\\])*)"\s*:`)

func classifySensitiveFields(body []byte, contentType string) []SensitiveField {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if !looksLikeJSONResponse(body, contentType) {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return classifySensitiveKeysInRawJSON(body)
	}

	fields := make([]SensitiveField, 0, 8)
	walkSensitiveValue("$", value, &fields, 0)
	return dedupeSensitiveFields(fields)
}

func classifySensitiveKeysInRawJSON(body []byte) []SensitiveField {
	matches := jsonKeyPattern.FindAllSubmatch(body, 500)
	if len(matches) == 0 {
		return nil
	}
	fields := make([]SensitiveField, 0, 8)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		key, err := strconv.Unquote(`"` + string(match[1]) + `"`)
		if err != nil {
			key = string(match[1])
		}
		if field, ok := classifySensitiveKey(key, "$."+key); ok {
			fields = append(fields, field)
			if len(fields) >= maxSensitiveFields {
				break
			}
		}
	}
	return dedupeSensitiveFields(fields)
}

func looksLikeJSONResponse(body []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func walkSensitiveValue(path string, value any, fields *[]SensitiveField, depth int) {
	if depth > 10 || len(*fields) >= maxSensitiveFields {
		return
	}
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := joinSensitivePath(path, key)
			if field, ok := classifySensitiveKey(key, childPath); ok {
				*fields = append(*fields, field)
				if len(*fields) >= maxSensitiveFields {
					return
				}
			}
			if field, ok := classifySensitiveValue(key, childPath, v[key]); ok {
				*fields = append(*fields, field)
				if len(*fields) >= maxSensitiveFields {
					return
				}
			}
			walkSensitiveValue(childPath, v[key], fields, depth+1)
			if len(*fields) >= maxSensitiveFields {
				return
			}
		}
	case []any:
		limit := len(v)
		if limit > 3 {
			limit = 3
		}
		for i := 0; i < limit; i++ {
			walkSensitiveValue(path+"[]", v[i], fields, depth+1)
			if len(*fields) >= maxSensitiveFields {
				return
			}
		}
	}
}

func classifySensitiveKey(key, path string) (SensitiveField, bool) {
	normalized := normalizeSensitiveKey(key)
	switch {
	case containsAny(normalized,
		"token", "accesstoken", "refreshtoken", "idtoken", "jwt", "authorization",
		"password", "passwd", "secret", "apikey", "privatekey", "clientsecret",
		"session", "cookie", "otp", "mfa", "bearer",
	):
		return SensitiveField{Path: path, Category: "auth_secret", Severity: "high"}, true
	case containsAny(normalized,
		"email", "phone", "mobile", "address", "firstname", "lastname", "fullname",
		"nationalid", "passport", "dob", "dateofbirth", "birthdate",
	):
		return SensitiveField{Path: path, Category: "pii", Severity: "medium"}, true
	case containsAny(normalized,
		"balance", "accountbalance", "portfolio", "cashbalance", "iban", "bankaccount",
		"cardnumber", "creditcard", "debitcard", "paymentmethod", "transactionamount",
	):
		return SensitiveField{Path: path, Category: "financial", Severity: "high"}, true
	case containsAny(normalized,
		"role", "roles", "permission", "permissions", "isadmin", "admin", "scope", "scopes",
	):
		return SensitiveField{Path: path, Category: "authorization", Severity: "high"}, true
	case containsAny(normalized,
		"userid", "customerid", "accountid", "tenantid", "orgid", "organizationid",
		"clientid", "walletid", "portfolioid", "beneficiaryid",
	):
		return SensitiveField{Path: path, Category: "identifier", Severity: "medium"}, true
	default:
		return SensitiveField{}, false
	}
}

func classifySensitiveValue(key, path string, value any) (SensitiveField, bool) {
	s, ok := value.(string)
	if !ok {
		return SensitiveField{}, false
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return SensitiveField{}, false
	}
	if emailValuePattern.MatchString(trimmed) && !strings.Contains(normalizeSensitiveKey(key), "email") {
		return SensitiveField{Path: path, Category: "pii_value", Severity: "medium"}, true
	}
	if looksLikeJWT(trimmed) {
		return SensitiveField{Path: path, Category: "auth_secret_value", Severity: "high"}, true
	}
	return SensitiveField{}, false
}

func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if len(part) < 10 {
			return false
		}
		for _, r := range part {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func normalizeSensitiveKey(key string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(key) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func joinSensitivePath(parent, key string) string {
	if parent == "" || parent == "$" {
		return "$." + key
	}
	return parent + "." + key
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func dedupeSensitiveFields(fields []SensitiveField) []SensitiveField {
	seen := map[string]bool{}
	out := make([]SensitiveField, 0, len(fields))
	for _, field := range fields {
		key := field.Path + "|" + field.Category
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, field)
	}
	return out
}

func sensitiveFieldRisk(fields []SensitiveField) (int, string) {
	score := 0
	for _, field := range fields {
		switch field.Severity {
		case "high":
			score += 35
		case "medium":
			score += 15
		case "low":
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 60:
		return score, "high"
	case score >= 25:
		return score, "medium"
	case score > 0:
		return score, "low"
	default:
		return 0, ""
	}
}

func summarizeSensitiveFields(fields []SensitiveField) string {
	if len(fields) == 0 {
		return ""
	}
	limit := len(fields)
	if limit > 6 {
		limit = 6
	}
	parts := make([]string, 0, limit+1)
	for i := 0; i < limit; i++ {
		parts = append(parts, fields[i].Category+":"+fields[i].Path)
	}
	if len(fields) > limit {
		parts = append(parts, "...+"+strconv.Itoa(len(fields)-limit))
	}
	return strings.Join(parts, ", ")
}
