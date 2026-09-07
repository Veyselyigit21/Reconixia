package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Veyselyigit21/Reconixia/internal/redact"
	"github.com/Veyselyigit21/Reconixia/internal/researchheaders"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

const (
	bodyLimit       = 128 * 1024
	defaultIDORRate = 2
	defaultIDORMax  = 50
)

type RequestSpec struct {
	Name    string            `json:"name,omitempty"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type AnalysisResult struct {
	Name            string           `json:"name,omitempty"`
	Method          string           `json:"method"`
	URL             string           `json:"url"`
	StatusA         int              `json:"status_a"`
	StatusB         int              `json:"status_b"`
	StatusUnauth    int              `json:"status_unauth,omitempty"`
	SizeA           int              `json:"size_a"`
	SizeB           int              `json:"size_b"`
	SizeUnauth      int              `json:"size_unauth,omitempty"`
	Classification  string           `json:"classification"`
	Risk            string           `json:"risk"`
	Confidence      string           `json:"confidence"`
	Note            string           `json:"note"`
	ObjectHints     []string         `json:"object_hints,omitempty"`
	SensitiveFields []SensitiveField `json:"sensitive_fields,omitempty"`
	Signals         []string         `json:"signals,omitempty"`
}

type Report struct {
	GeneratedAt string           `json:"generated_at"`
	Target      string           `json:"target,omitempty"`
	Source      string           `json:"source"`
	Policy      ProgramPolicy    `json:"policy,omitempty"`
	Count       int              `json:"count"`
	Results     []AnalysisResult `json:"results"`
	Warnings    []string         `json:"warnings,omitempty"`
}

type ProgramPolicy struct {
	Name               string   `json:"name,omitempty"`
	Target             string   `json:"target,omitempty"`
	ResearchHeader     string   `json:"research_header,omitempty"`
	H1User             string   `json:"h1_user,omitempty"`
	Rate               int      `json:"rate,omitempty"`
	MaxRequests        int      `json:"max_requests,omitempty"`
	AllowMutating      bool     `json:"allow_mutating,omitempty"`
	AllowedMethods     []string `json:"allowed_methods,omitempty"`
	BlockedURLKeywords []string `json:"blocked_url_keywords,omitempty"`
	RequireOwned       bool     `json:"require_owned_accounts,omitempty"`
	Notes              []string `json:"notes,omitempty"`
}

type SensitiveField struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type responseSample struct {
	Status      int
	ContentType string
	Size        int
	Hash        string
	Body        []byte
	Err         error
}

func main() {
	var (
		target         = flag.String("target", "", "scope root, e.g. whatnot.com")
		input          = flag.String("input", "", "JSONL request specs exported/curated for owned-account testing")
		harPath        = flag.String("har", "", "HAR file from browser/Burp containing owned-account requests")
		rulesPath      = flag.String("rules", "", "program policy JSON with rate/method/header/safety rules")
		output         = flag.String("output", "", "output JSON path")
		authA          = flag.String("auth-a", "", "account A auth header, e.g. 'Authorization: Bearer ...' (prefer env)")
		authB          = flag.String("auth-b", "", "account B auth header, e.g. 'Authorization: Bearer ...' (prefer env)")
		authAEnv       = flag.String("auth-a-env", "RECONIXIA_IDOR_AUTH_A", "env var containing account A auth header")
		authBEnv       = flag.String("auth-b-env", "RECONIXIA_IDOR_AUTH_B", "env var containing account B auth header")
		cookieA        = flag.String("cookie-a", "", "account A Cookie header value (prefer env)")
		cookieB        = flag.String("cookie-b", "", "account B Cookie header value (prefer env)")
		cookieAEnv     = flag.String("cookie-a-env", "RECONIXIA_IDOR_COOKIE_A", "env var containing account A cookie")
		cookieBEnv     = flag.String("cookie-b-env", "RECONIXIA_IDOR_COOKIE_B", "env var containing account B cookie")
		h1User         = flag.String("h1-user", "", "HackerOne username for X-HackerOne-Research header")
		researchHeader = flag.String("research-header", "", "custom research attribution header name")
		rate           = flag.Int("rate", defaultIDORRate, "requests per second; keep low for production bug bounty testing")
		maxRequests    = flag.Int("max", defaultIDORMax, "maximum request specs to replay")
		allowMutating  = flag.Bool("allow-mutating", false, "allow POST/PUT/PATCH/DELETE replay; use only with owned test data")
		unauthBaseline = flag.Bool("unauth-baseline", true, "send a no-auth baseline request to reduce public endpoint false positives")
		labMode        = flag.Bool("lab-mode", false, "allow loopback/private IP targets for authorized local lab testing only")
	)
	flag.Parse()

	if *input == "" && *harPath == "" {
		fatal("input veya har gerekli")
	}
	policy := ProgramPolicy{}
	if *rulesPath != "" {
		var err error
		policy, err = loadProgramPolicy(*rulesPath)
		if err != nil {
			fatal(err.Error())
		}
		applyProgramPolicy(policy, target, h1User, researchHeader, rate, maxRequests, allowMutating)
	}
	if *h1User != "" {
		_ = os.Setenv("RECONIXIA_H1_USERNAME", *h1User)
	}
	if *researchHeader != "" {
		_ = os.Setenv("RECONIXIA_RESEARCH_HEADER_NAME", *researchHeader)
	}
	if *labMode {
		_ = os.Setenv("RECONIXIA_LAB_MODE", "1")
	}

	*authA = firstNonEmpty(*authA, os.Getenv(*authAEnv))
	*authB = firstNonEmpty(*authB, os.Getenv(*authBEnv))
	*cookieA = firstNonEmpty(*cookieA, os.Getenv(*cookieAEnv))
	*cookieB = firstNonEmpty(*cookieB, os.Getenv(*cookieBEnv))
	if *authA == "" && *cookieA == "" {
		fatal("account A auth gerekli: -auth-a veya " + *authAEnv)
	}
	if *authB == "" && *cookieB == "" {
		fatal("account B auth gerekli: -auth-b veya " + *authBEnv)
	}

	specs, source, err := loadSpecs(*input, *harPath)
	if err != nil {
		fatal(err.Error())
	}
	if len(specs) == 0 {
		fatal("test edilecek request bulunamadi")
	}

	scopeRules, normalizedTarget := scopeRulesFor(*target)
	client := safety.SafeHTTPClient(15 * time.Second)
	results, warnings := analyzeSpecs(context.Background(), client, specs, analyzeOptions{
		scopeRules:      scopeRules,
		authA:           *authA,
		authB:           *authB,
		cookieA:         *cookieA,
		cookieB:         *cookieB,
		rate:            *rate,
		maxRequests:     *maxRequests,
		allowMutating:   *allowMutating,
		unauthBaseline:  *unauthBaseline,
		normalizedScope: normalizedTarget,
		policy:          policy,
	})

	report := Report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Target:      normalizedTarget,
		Source:      source,
		Policy:      policy,
		Count:       len(results),
		Results:     redactResults(results),
		Warnings:    warnings,
	}
	outPath := *output
	if outPath == "" {
		outPath = defaultOutputPath(normalizedTarget)
	}
	if err := writeReport(outPath, report); err != nil {
		fatal(err.Error())
	}
	fmt.Println("[+] IDOR/BOLA analysis:", outPath)
	fmt.Println("[+] Markdown:", strings.TrimSuffix(outPath, filepath.Ext(outPath))+".md")
}

type analyzeOptions struct {
	scopeRules      []string
	authA           string
	authB           string
	cookieA         string
	cookieB         string
	rate            int
	maxRequests     int
	allowMutating   bool
	unauthBaseline  bool
	normalizedScope string
	policy          ProgramPolicy
}

func analyzeSpecs(ctx context.Context, client *http.Client, specs []RequestSpec, opts analyzeOptions) ([]AnalysisResult, []string) {
	if opts.rate < 1 {
		opts.rate = 1
	}
	if opts.maxRequests < 1 || opts.maxRequests > len(specs) {
		opts.maxRequests = len(specs)
	}
	ticker := time.NewTicker(time.Second / time.Duration(opts.rate))
	defer ticker.Stop()

	results := []AnalysisResult{}
	warnings := []string{}
	for _, spec := range specs {
		if len(results) >= opts.maxRequests {
			break
		}
		spec.Method = strings.ToUpper(firstNonEmpty(spec.Method, http.MethodGet))
		if !requestAllowedByPolicy(spec, opts.allowMutating, opts.policy.AllowedMethods) {
			warnings = append(warnings, fmt.Sprintf("skipped method %s by policy %s", spec.Method, redact.String(spec.URL)))
			continue
		}
		if blockedByPolicy(spec.URL, opts.policy.BlockedURLKeywords) {
			warnings = append(warnings, "skipped URL blocked by program policy: "+redact.String(spec.URL))
			continue
		}
		if !safeInScope(spec.URL, opts.scopeRules) {
			warnings = append(warnings, "skipped out-of-scope or unsafe URL: "+redact.String(spec.URL))
			continue
		}

		<-ticker.C
		a := replay(ctx, client, spec, opts.authA, opts.cookieA)
		<-ticker.C
		b := replay(ctx, client, spec, opts.authB, opts.cookieB)
		var unauth responseSample
		if opts.unauthBaseline && canUnauthBaseline(spec) {
			<-ticker.C
			unauth = replay(ctx, client, spec, "", "")
		}
		results = append(results, classify(spec, a, b, unauth))
	}
	sort.Slice(results, func(i, j int) bool {
		if riskRank(results[i].Risk) != riskRank(results[j].Risk) {
			return riskRank(results[i].Risk) > riskRank(results[j].Risk)
		}
		return results[i].URL < results[j].URL
	})
	return results, warnings
}

func replay(ctx context.Context, client *http.Client, spec RequestSpec, authHeader, cookie string) responseSample {
	var body io.Reader
	if spec.Body != "" {
		body = strings.NewReader(spec.Body)
	}
	req, err := http.NewRequestWithContext(ctx, spec.Method, spec.URL, body)
	if err != nil {
		return responseSample{Err: err}
	}
	for k, v := range spec.Headers {
		if skipCapturedHeader(k) {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	researchheaders.Apply(req)
	if authHeader != "" {
		if name, value, ok := splitHeader(authHeader); ok {
			req.Header.Set(name, value)
		}
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return responseSample{Err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	sum := sha256.Sum256(b)
	return responseSample{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Size:        len(b),
		Hash:        hex.EncodeToString(sum[:]),
		Body:        b,
	}
}

func canUnauthBaseline(spec RequestSpec) bool {
	return strings.EqualFold(spec.Method, http.MethodGet) || isReadOnlyGraphQLPost(spec)
}

func isGraphQLRequest(spec RequestSpec) bool {
	if strings.Contains(strings.ToLower(spec.URL), "graphql") {
		return true
	}
	var payload struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal([]byte(spec.Body), &payload); err != nil {
		return false
	}
	return strings.TrimSpace(payload.Query) != "" || strings.TrimSpace(payload.OperationName) != ""
}

func graphqlDenied(body []byte) bool {
	if len(bytes.TrimSpace(body)) == 0 {
		return false
	}
	var parsed struct {
		Errors []struct {
			Message    string         `json:"message"`
			Extensions map[string]any `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Errors) == 0 {
		return false
	}
	for _, item := range parsed.Errors {
		text := strings.ToLower(item.Message + " " + fmt.Sprint(item.Extensions))
		if containsAny(text,
			"unauthorized",
			"unauthenticated",
			"not authenticated",
			"authentication required",
			"forbidden",
			"permission",
			"not authorized",
			"login required",
			"access denied",
		) {
			return true
		}
	}
	return false
}

func graphqlHasMeaningfulData(body []byte) bool {
	if len(bytes.TrimSpace(body)) == 0 {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	data, ok := payload["data"]
	if !ok {
		return false
	}
	return meaningfulJSONValue(data)
}

func meaningfulJSONValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case bool, float64:
		return true
	case []any:
		for _, item := range t {
			if meaningfulJSONValue(item) {
				return true
			}
		}
		return false
	case map[string]any:
		for key, value := range t {
			if strings.EqualFold(key, "__typename") {
				continue
			}
			if meaningfulJSONValue(value) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func classify(spec RequestSpec, a, b, unauth responseSample) AnalysisResult {
	fields := classifySensitiveFields(b.Body, b.ContentType)
	if len(fields) == 0 {
		fields = classifySensitiveFields(a.Body, a.ContentType)
	}
	hints := objectHintsForSpec(spec)
	signals := comparisonSignals(spec, a, b, unauth, fields, hints)
	result := AnalysisResult{
		Name:            spec.Name,
		Method:          spec.Method,
		URL:             spec.URL,
		StatusA:         a.Status,
		StatusB:         b.Status,
		StatusUnauth:    unauth.Status,
		SizeA:           a.Size,
		SizeB:           b.Size,
		SizeUnauth:      unauth.Size,
		ObjectHints:     hints,
		SensitiveFields: fields,
		Signals:         signals,
	}
	switch {
	case a.Err != nil:
		result.Classification = "baseline_failed"
		result.Risk = "info"
		result.Confidence = "low"
		result.Note = "account A request failed; cannot compare"
	case b.Err != nil:
		result.Classification = "replay_failed"
		result.Risk = "info"
		result.Confidence = "low"
		result.Note = "account B request failed; cannot compare"
	case is2xx(a.Status) && graphqlDenied(a.Body):
		result.Classification = "baseline_failed"
		result.Risk = "info"
		result.Confidence = "low"
		result.Note = "account A received a GraphQL authorization error; capture/auth may be stale"
	case is2xx(a.Status) && is2xx(b.Status) && graphqlDenied(b.Body):
		result.Classification = "protected"
		result.Risk = "info"
		result.Confidence = "high"
		result.Note = "account B received a GraphQL authorization error for account A request"
	case isGraphQLRequest(spec) && is2xx(a.Status) && !graphqlDenied(a.Body) && !graphqlHasMeaningfulData(a.Body):
		result.Classification = "empty_or_anonymous"
		result.Risk = "info"
		result.Confidence = "high"
		result.Note = "account A response has no meaningful GraphQL account data; refresh cookies or capture object-detail requests with owned IDs"
	case is2xx(a.Status) && is2xx(b.Status) && is2xx(unauth.Status) && !graphqlDenied(unauth.Body) && similar(a, unauth):
		result.Classification = "public_endpoint"
		result.Risk = "info"
		result.Confidence = "medium"
		result.Note = "no-auth baseline can access similar response; not an IDOR signal by itself"
	case is2xx(a.Status) && (b.Status == http.StatusUnauthorized || b.Status == http.StatusForbidden || b.Status == http.StatusNotFound):
		result.Classification = "protected"
		result.Risk = "info"
		result.Confidence = "high"
		result.Note = "account B cannot access account A request"
	case is2xx(a.Status) && is2xx(b.Status) && sameMeaningfulResponse(a, b) && isObjectDetailCandidate(hints):
		result.Classification = "possible_idor"
		result.Risk = idorRisk(fields, hints)
		result.Confidence = idorConfidence(fields, hints, a, b)
		result.Note = "account B received the same meaningful response for an object-detail request captured from account A; manually verify with owned accounts only"
	case is2xx(a.Status) && is2xx(b.Status) && sameMeaningfulResponse(a, b):
		result.Classification = "same_authenticated_response"
		result.Risk = idorRisk(fields, hints)
		result.Confidence = "low"
		result.Note = "account A and B received the same authenticated response, but the request has no strong object-id signal; capture an owned object-detail request before treating this as IDOR"
	case is2xx(a.Status) && is2xx(b.Status):
		result.Classification = "account_scoped"
		result.Risk = "info"
		result.Confidence = "high"
		result.Note = "both accounts received successful but different responses; this usually means the endpoint is account-scoped rather than IDOR"
	case a.Status > 0 && b.Status > 0:
		result.Classification = "inconclusive"
		result.Risk = "info"
		result.Confidence = "low"
		result.Note = "responses differ or are not successful enough for an IDOR signal"
	default:
		result.Classification = "unknown"
		result.Risk = "info"
		result.Confidence = "low"
		result.Note = "no useful response"
	}
	return result
}

func loadSpecs(input, harPath string) ([]RequestSpec, string, error) {
	if input != "" {
		specs, err := loadJSONL(input)
		return specs, input, err
	}
	specs, err := loadHAR(harPath)
	return specs, harPath, err
}

func loadProgramPolicy(path string) (ProgramPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProgramPolicy{}, err
	}
	var policy ProgramPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return ProgramPolicy{}, fmt.Errorf("invalid program policy JSON: %w", err)
	}
	policy.AllowedMethods = normalizeMethods(policy.AllowedMethods)
	policy.BlockedURLKeywords = normalizeKeywords(policy.BlockedURLKeywords)
	return policy, nil
}

func applyProgramPolicy(policy ProgramPolicy, target, h1User, researchHeader *string, rate, maxRequests *int, allowMutating *bool) {
	if strings.TrimSpace(*target) == "" && strings.TrimSpace(policy.Target) != "" {
		*target = strings.TrimSpace(policy.Target)
	}
	if strings.TrimSpace(*h1User) == "" && strings.TrimSpace(policy.H1User) != "" {
		*h1User = strings.TrimSpace(policy.H1User)
	}
	if strings.TrimSpace(*researchHeader) == "" && strings.TrimSpace(policy.ResearchHeader) != "" {
		*researchHeader = strings.TrimSpace(policy.ResearchHeader)
	}
	if *rate == defaultIDORRate && policy.Rate > 0 {
		*rate = policy.Rate
	}
	if *maxRequests == defaultIDORMax && policy.MaxRequests > 0 {
		*maxRequests = policy.MaxRequests
	}
	if policy.AllowMutating {
		*allowMutating = true
	}
}

func normalizeMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	seen := map[string]bool{}
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" || seen[method] {
			continue
		}
		seen[method] = true
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

func normalizeKeywords(keywords []string) []string {
	out := make([]string, 0, len(keywords))
	seen := map[string]bool{}
	for _, keyword := range keywords {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword == "" || seen[keyword] {
			continue
		}
		seen[keyword] = true
		out = append(out, keyword)
	}
	sort.Strings(out)
	return out
}

func loadJSONL(path string) ([]RequestSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []RequestSpec{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var spec RequestSpec
		if err := json.Unmarshal([]byte(line), &spec); err != nil {
			return nil, fmt.Errorf("invalid JSONL request: %w", err)
		}
		out = append(out, spec)
	}
	return out, sc.Err()
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				URL     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				PostData *struct {
					Text string `json:"text"`
				} `json:"postData,omitempty"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func loadHAR(path string) ([]RequestSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var har harFile
	if err := json.Unmarshal(raw, &har); err != nil {
		return nil, err
	}
	out := []RequestSpec{}
	seen := map[string]bool{}
	for _, entry := range har.Log.Entries {
		req := entry.Request
		if req.URL == "" {
			continue
		}
		headers := map[string]string{}
		for _, h := range req.Headers {
			if skipCapturedHeader(h.Name) {
				continue
			}
			headers[h.Name] = h.Value
		}
		body := ""
		if req.PostData != nil {
			body = req.PostData.Text
		}
		key := req.Method + " " + req.URL + " " + body
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RequestSpec{Method: req.Method, URL: req.URL, Headers: headers, Body: body})
	}
	return out, nil
}

func writeReport(path string, report Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	return os.WriteFile(strings.TrimSuffix(path, filepath.Ext(path))+".md", []byte(markdown(report)), 0600)
}

func markdown(report Report) string {
	var b strings.Builder
	b.WriteString("# Reconixia IDOR/BOLA Analysis\n\n")
	b.WriteString("Source: `" + redact.String(report.Source) + "`\n\n")
	if report.Target != "" {
		b.WriteString("Target: `" + report.Target + "`\n\n")
	}
	if report.Policy.Name != "" {
		b.WriteString("Policy: `" + report.Policy.Name + "`\n\n")
	}
	if len(report.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range report.Warnings {
			b.WriteString("- " + w + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## Results\n\n")
	for _, r := range report.Results {
		fields := summarizeSensitiveFields(r.SensitiveFields)
		if fields == "" {
			fields = "-"
		}
		hints := strings.Join(r.ObjectHints, ", ")
		if hints == "" {
			hints = "-"
		}
		signals := strings.Join(r.Signals, ", ")
		if signals == "" {
			signals = "-"
		}
		b.WriteString(fmt.Sprintf("- **%s** `%s/%s` A:%d B:%d unauth:%d `%s` fields:%s hints:%s signals:%s\n  %s\n",
			r.Classification, r.Risk, r.Confidence, r.StatusA, r.StatusB, r.StatusUnauth, redact.String(r.URL), fields, hints, signals, r.Note))
	}
	return b.String()
}

func defaultOutputPath(target string) string {
	if target == "" {
		target = "idor"
	}
	return filepath.Join("results", target, "idor_analysis.json")
}

func scopeRulesFor(target string) ([]string, string) {
	if strings.TrimSpace(target) == "" {
		return nil, ""
	}
	normalized, ok := safety.NormalizeTarget(target)
	if !ok {
		fatal("gecersiz target scope: " + target)
	}
	return []string{normalized, "*." + normalized}, normalized
}

func safeInScope(rawURL string, rules []string) bool {
	if !safety.IsSafeFetchURL(rawURL) {
		return false
	}
	if len(rules) == 0 {
		return true
	}
	return safety.ScopeAllowsURL(rawURL, rules)
}

func methodAllowed(method string, allowMutating bool) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return allowMutating
	default:
		return false
	}
}

func methodAllowedByPolicy(method string, allowMutating bool, allowedMethods []string) bool {
	return requestAllowedByPolicy(RequestSpec{Method: method}, allowMutating, allowedMethods)
}

func requestAllowedByPolicy(spec RequestSpec, allowMutating bool, allowedMethods []string) bool {
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = http.MethodGet
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if len(allowedMethods) == 0 {
		if isReadOnlyGraphQLPost(spec) {
			return true
		}
		return methodAllowed(method, allowMutating)
	}
	found := false
	for _, allowed := range allowedMethods {
		if method == allowed {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if isMutatingMethod(method) && !allowMutating && !isReadOnlyGraphQLPost(spec) {
		return false
	}
	return true
}

func isReadOnlyGraphQLPost(spec RequestSpec) bool {
	if strings.ToUpper(strings.TrimSpace(spec.Method)) != http.MethodPost {
		return false
	}
	if !strings.Contains(strings.ToLower(spec.URL), "graphql") {
		return false
	}
	var payload struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(spec.Body), &payload); err != nil {
		return false
	}
	query := strings.TrimSpace(payload.Query)
	if query == "" {
		return false
	}
	query = strings.TrimSpace(strings.TrimPrefix(query, "\ufeff"))
	if strings.HasPrefix(query, "#") {
		for _, line := range strings.Split(query, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			query = line
			break
		}
	}
	lower := strings.ToLower(query)
	return strings.HasPrefix(lower, "query ") ||
		strings.HasPrefix(lower, "query{") ||
		strings.HasPrefix(lower, "query\t") ||
		strings.HasPrefix(lower, "fragment ")
}

func isMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func blockedByPolicy(rawURL string, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}
	u := strings.ToLower(rawURL)
	for _, keyword := range keywords {
		if keyword != "" && strings.Contains(u, keyword) {
			return true
		}
	}
	return false
}

func skipCapturedHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "authorization", "cookie", "host", "content-length", "connection", "proxy-authorization":
		return true
	default:
		return strings.HasPrefix(n, ":")
	}
}

func splitHeader(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	return name, value, name != "" && value != ""
}

func is2xx(status int) bool {
	return status >= 200 && status < 300
}

func similar(a, b responseSample) bool {
	if a.Hash != "" && a.Hash == b.Hash {
		return true
	}
	if a.Size == 0 && b.Size == 0 {
		return true
	}
	minSize := a.Size
	maxSize := b.Size
	if minSize > maxSize {
		minSize, maxSize = maxSize, minSize
	}
	if maxSize == 0 {
		return false
	}
	return float64(minSize)/float64(maxSize) >= 0.90
}

func sameMeaningfulResponse(a, b responseSample) bool {
	if len(bytes.TrimSpace(a.Body)) == 0 || len(bytes.TrimSpace(b.Body)) == 0 {
		return false
	}
	if a.Hash != "" && a.Hash == b.Hash {
		return true
	}
	if ah, ok := canonicalJSONHash(a.Body); ok {
		if bh, ok := canonicalJSONHash(b.Body); ok && ah == bh {
			return true
		}
	}
	return false
}

func canonicalJSONHash(body []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return "", false
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), true
}

func comparisonSignals(spec RequestSpec, a, b, unauth responseSample, fields []SensitiveField, hints []string) []string {
	signals := []string{}
	if sameMeaningfulResponse(a, b) {
		signals = append(signals, "same_a_b_response")
	}
	if is2xx(unauth.Status) && similar(a, unauth) && !graphqlDenied(unauth.Body) {
		signals = append(signals, "unauth_similar")
	}
	if graphqlDenied(a.Body) {
		signals = append(signals, "account_a_graphql_denied")
	}
	if graphqlDenied(b.Body) {
		signals = append(signals, "account_b_graphql_denied")
	}
	if isGraphQLRequest(spec) && is2xx(a.Status) && !graphqlHasMeaningfulData(a.Body) {
		signals = append(signals, "empty_graphql_data")
	}
	if len(fields) > 0 {
		signals = append(signals, "sensitive_fields")
	}
	if isObjectDetailCandidate(hints) {
		signals = append(signals, "object_detail_candidate")
	}
	if op := graphQLOperationName(spec); op != "" {
		signals = append(signals, "graphql_operation:"+op)
	}
	return dedupeStrings(signals)
}

func isObjectDetailCandidate(hints []string) bool {
	for _, hint := range hints {
		switch hint {
		case "object_id_in_path", "object_id_in_query", "object_id_in_graphql_variables":
			return true
		}
	}
	return false
}

func objectHintsForSpec(spec RequestSpec) []string {
	set := map[string]bool{}
	for _, hint := range objectHints(spec.URL) {
		set[hint] = true
	}
	for _, hint := range graphQLObjectHints(spec) {
		set[hint] = true
	}
	out := make([]string, 0, len(set))
	for hint := range set {
		out = append(out, hint)
	}
	sort.Strings(out)
	return out
}

func objectHints(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	path := strings.ToLower(u.Path)
	for _, term := range []string{
		"user", "users", "account", "accounts", "address", "addresses", "order", "orders",
		"payment", "payments", "wallet", "wallets", "seller", "inventory", "livestream",
		"auction", "message", "messages", "profile", "shipping", "payout", "invoice",
	} {
		if strings.Contains(path, term) {
			set[term] = true
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		part = strings.TrimSpace(part)
		if looksLikeObjectID(part) {
			set["object_id_in_path"] = true
		}
	}
	for key := range u.Query() {
		n := normalizeKey(key)
		if strings.Contains(n, "id") || strings.Contains(n, "user") || strings.Contains(n, "account") || strings.Contains(n, "order") {
			set["object_id_in_query"] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func graphQLObjectHints(spec RequestSpec) []string {
	if !isGraphQLRequest(spec) {
		return nil
	}
	set := map[string]bool{}
	op := strings.ToLower(graphQLOperationName(spec))
	for _, term := range []string{
		"user", "account", "address", "order", "payment", "wallet", "seller", "inventory",
		"listing", "livestream", "auction", "message", "conversation", "shipping", "shipment",
		"payout", "invoice",
	} {
		if strings.Contains(op, term) {
			set[term] = true
		}
	}
	var payload struct {
		Variables any `json:"variables"`
	}
	if err := json.Unmarshal([]byte(spec.Body), &payload); err == nil {
		walkGraphQLVariableHints("$", payload.Variables, set, 0)
	}
	out := make([]string, 0, len(set))
	for hint := range set {
		out = append(out, hint)
	}
	sort.Strings(out)
	return out
}

func graphQLOperationName(spec RequestSpec) string {
	if u, err := url.Parse(spec.URL); err == nil {
		if op := strings.TrimSpace(u.Query().Get("operationName")); op != "" {
			return op
		}
	}
	var payload struct {
		OperationName string `json:"operationName"`
	}
	if err := json.Unmarshal([]byte(spec.Body), &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.OperationName)
}

func walkGraphQLVariableHints(path string, value any, set map[string]bool, depth int) {
	if depth > 8 || value == nil {
		return
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			normalized := normalizeKey(key)
			childPath := path + "." + key
			if variableKeyLooksObjectID(normalized) && valueLooksObjectID(child) {
				set["object_id_in_graphql_variables"] = true
			}
			for _, term := range []string{"user", "account", "order", "shipment", "conversation", "listing", "inventory", "payout", "seller"} {
				if strings.Contains(normalized, term) {
					set[term] = true
				}
			}
			walkGraphQLVariableHints(childPath, child, set, depth+1)
		}
	case []any:
		for _, child := range v {
			walkGraphQLVariableHints(path+"[]", child, set, depth+1)
		}
	}
}

func variableKeyLooksObjectID(normalized string) bool {
	return normalized == "id" ||
		strings.HasSuffix(normalized, "id") ||
		strings.Contains(normalized, "uuid") ||
		strings.Contains(normalized, "slug")
}

func valueLooksObjectID(value any) bool {
	switch v := value.(type) {
	case string:
		return looksLikeObjectID(v)
	case json.Number:
		return true
	case float64:
		return v > 0
	case []any:
		for _, item := range v {
			if valueLooksObjectID(item) {
				return true
			}
		}
	}
	return false
}

func looksLikeObjectID(value string) bool {
	if len(value) < 4 {
		return false
	}
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return true
	}
	if regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(value) {
		return true
	}
	return regexp.MustCompile(`(?i)^[a-z0-9_-]{12,}$`).MatchString(value)
}

func idorRisk(fields []SensitiveField, hints []string) string {
	hasHigh := false
	for _, f := range fields {
		if f.Severity == "high" {
			hasHigh = true
			break
		}
	}
	switch {
	case hasHigh || len(fields) >= 3:
		return "high"
	case len(fields) > 0 || len(hints) > 0:
		return "medium"
	default:
		return "low"
	}
}

func idorConfidence(fields []SensitiveField, hints []string, a, b responseSample) string {
	switch {
	case len(fields) > 0 && len(hints) > 0:
		return "high"
	case len(fields) > 0 || len(hints) > 0 || similar(a, b):
		return "medium"
	default:
		return "low"
	}
}

func riskRank(risk string) int {
	switch risk {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func redactResults(in []AnalysisResult) []AnalysisResult {
	out := make([]AnalysisResult, len(in))
	copy(out, in)
	for i := range out {
		out[i].URL = redact.String(out[i].URL)
		out[i].Note = redact.String(out[i].Note)
		for j := range out[i].SensitiveFields {
			out[i].SensitiveFields[j].Path = redact.String(out[i].SensitiveFields[j].Path)
		}
	}
	return out
}

var jsonKeyPattern = regexp.MustCompile(`"((?:\\.|[^"\\])*)"\s*:`)
var emailValuePattern = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

func classifySensitiveFields(body []byte, contentType string) []SensitiveField {
	if len(bytes.TrimSpace(body)) == 0 || !looksLikeJSON(body, contentType) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return classifySensitiveKeysInRawJSON(body)
	}
	fields := []SensitiveField{}
	walkSensitive("$", value, &fields, 0)
	return dedupeSensitiveFields(fields)
}

func looksLikeJSON(body []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func classifySensitiveKeysInRawJSON(body []byte) []SensitiveField {
	matches := jsonKeyPattern.FindAllSubmatch(body, 500)
	fields := []SensitiveField{}
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
		}
	}
	return dedupeSensitiveFields(fields)
}

func walkSensitive(path string, value any, fields *[]SensitiveField, depth int) {
	if depth > 10 || len(*fields) >= 32 {
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
			child := path + "." + key
			if field, ok := classifySensitiveKey(key, child); ok {
				*fields = append(*fields, field)
			}
			if field, ok := classifySensitiveValue(key, child, v[key]); ok {
				*fields = append(*fields, field)
			}
			walkSensitive(child, v[key], fields, depth+1)
		}
	case []any:
		limit := len(v)
		if limit > 3 {
			limit = 3
		}
		for i := 0; i < limit; i++ {
			walkSensitive(path+"[]", v[i], fields, depth+1)
		}
	}
}

func classifySensitiveKey(key, path string) (SensitiveField, bool) {
	n := normalizeKey(key)
	switch {
	case containsAny(n, "token", "authorization", "password", "secret", "apikey", "privatekey", "session", "cookie", "otp", "mfa"):
		return SensitiveField{Path: path, Category: "auth_secret", Severity: "high"}, true
	case containsAny(n, "email", "phone", "mobile", "address", "firstname", "lastname", "fullname", "nationalid", "passport", "dob", "birthdate"):
		return SensitiveField{Path: path, Category: "pii", Severity: "medium"}, true
	case containsAny(n, "balance", "portfolio", "iban", "bankaccount", "cardnumber", "paymentmethod", "transactionamount"):
		return SensitiveField{Path: path, Category: "financial", Severity: "high"}, true
	case containsAny(n, "role", "permission", "isadmin", "scope"):
		return SensitiveField{Path: path, Category: "authorization", Severity: "high"}, true
	case containsAny(n, "userid", "customerid", "accountid", "tenantid", "orgid", "clientid", "walletid", "portfolioid", "orderid", "sellerid"):
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
	if emailValuePattern.MatchString(strings.TrimSpace(s)) && !strings.Contains(normalizeKey(key), "email") {
		return SensitiveField{Path: path, Category: "pii_value", Severity: "medium"}, true
	}
	return SensitiveField{}, false
}

func normalizeKey(key string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(key) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
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
	out := []SensitiveField{}
	for _, f := range fields {
		key := f.Path + "|" + f.Category
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
		parts = append(parts, fmt.Sprintf("...+%d", len(fields)-limit))
	}
	return strings.Join(parts, ", ")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "hata:", msg)
	os.Exit(1)
}
