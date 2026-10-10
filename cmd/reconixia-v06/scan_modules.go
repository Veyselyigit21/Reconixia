package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/headers"
	"github.com/Veyselyigit21/Reconixia/internal/researchheaders"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
	"github.com/Veyselyigit21/Reconixia/internal/secrets"
)

func analyzeHeaders(live []string, p Profile, rules []string, client *http.Client) []Finding {
	out := []Finding{}
	for _, u := range safety.FilterSafeScopedURLs(live, rules) {
		for _, hf := range headers.AnalyzeURL(client, u, rules) {
			out = append(out, Finding{
				Type:       hf.Type,
				URL:        hf.URL,
				Status:     hf.Status,
				Confidence: hf.Confidence,
				Note:       hf.Note,
			})
		}
	}
	return out
}

// ── Secret tarama — FIX: internal/secrets paketi kullanılıyor ───────────────

func secretScan(ctx context.Context, js []string, p Profile, rules []string, client *http.Client) []Finding {
	findings := []Finding{}
	for _, u := range safety.FilterSafeScopedURLs(js, rules) {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		body, ok := fetchText(client, u)
		if !ok {
			continue
		}
		// FIX: internal/secrets.Scan() — 11 pattern (eski: 4 inline pattern)
		for _, m := range secrets.Scan(body) {
			findings = append(findings, Finding{
				Type:       m.Type,
				URL:        u,
				Status:     0,
				Confidence: m.Confidence,
				Note:       m.Note,
			})
		}
	}
	return findings
}

// ── Bulgu deduplication — FIX: aynı type aynı URL'de tekrar etmiyor ─────────

func deduplicateFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	out := []Finding{}
	for _, f := range in {
		key := f.Type + "|" + f.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// ── Scope ve profil ──────────────────────────────────────────────────────────

func loadScope(path, target string, warnings *[]string) []string {
	defaultRules := []string{target, "*." + target}
	if path == "" {
		return defaultRules
	}
	lines, err := readLines(path)
	if err != nil || len(lines) == 0 {
		*warnings = append(*warnings, "scope okunamadı; otomatik wildcard kullanıldı")
		return defaultRules
	}
	hasAllow := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "!") {
			hasAllow = true
			break
		}
	}
	if !hasAllow {
		*warnings = append(*warnings, "scope sadece deny kuralı içeriyor; otomatik wildcard allow eklendi")
		lines = append(defaultRules, lines...)
	}
	return lines
}

func filterHostsByScope(hosts []string, rules []string) []string {
	out := []string{}
	for _, h := range hosts {
		h, ok := safety.NormalizeTarget(h)
		if !ok {
			continue
		}
		for _, scheme := range []string{"https://", "http://"} {
			if safety.ScopeAllowsURL(scheme+h, rules) {
				out = append(out, h)
				break
			}
		}
	}
	return uniq(out)
}

func profile(name string) Profile {
	switch strings.ToLower(name) {
	case "stealth":
		return Profile{"stealth", 2, 3, 10 * time.Second, 60 * time.Second}
	case "fast":
		return Profile{"fast", 20, 25, 8 * time.Second, 120 * time.Second}
	default:
		// FIX: GAUTimeout profile'a göre ayarlandı
		return Profile{"balanced", 8, 10, 10 * time.Second, 180 * time.Second}
	}
}

func defaultSeverity(prof string) string {
	if prof == "stealth" {
		return "info,low"
	}
	return "info,low,medium"
}

// ── Harici araçlar ───────────────────────────────────────────────────────────

func subfinder(target, out string) ([]string, error) {
	if _, err := exec.LookPath("subfinder"); err != nil {
		return []string{target}, fmt.Errorf("subfinder yok; root domain kullanılacak")
	}
	cmd := exec.Command("subfinder", "-d", target, "-silent", "-o", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("subfinder hata: %v %s", err, string(b))
	}
	lines, _ := readLines(out)
	return uniq(lines), nil
}

// httpxLive probes hosts and writes httpx JSONL (url + tech fingerprints) to
// detailedPath. It returns the bare live URL list; the JSONL is kept so the
// tech-priority stage can rank fingerprints without a second probe.
func httpxLive(in, detailedPath string, p Profile) ([]string, error) {
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx yok; internal fallback kullanılacak")
	}
	cmd := exec.Command("httpx",
		"-l", in,
		"-silent",
		"-json",
		"-follow-host-redirects",
		"-status-code",
		"-title",
		"-tech-detect",
		"-rate-limit", fmt.Sprint(p.Rate),
		"-threads", fmt.Sprint(p.Threads),
		"-o", detailedPath,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	lines, _ := readLines(detailedPath)
	out := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var hl struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(line), &hl) == nil && hl.URL != "" {
			out = append(out, hl.URL)
		}
	}
	return uniq(out), nil
}

func nuclei(in, out string, p Profile, severity string, dast bool) error {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return fmt.Errorf("nuclei yok; atlandı")
	}
	args := []string{
		"-l", in,
		"-severity", severity,
		"-rate-limit", fmt.Sprint(p.Rate),
		"-silent",
		"-o", out,
	}
	if dast {
		// -dast: yalnızca fuzzing/DAST şablonlarını çalıştırır (aktif test).
		args = append(args, "-dast")
	}
	if templates := nucleiTemplatesDir(); templates != "" {
		args = append(args, "-t", templates)
	}
	cmd := exec.Command("nuclei", args...)
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		fmt.Print(string(output))
	}
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(output))
	if strings.Contains(strings.ToLower(msg), "no templates provided") {
		return fmt.Errorf("nuclei template yok; 'nuclei -update-templates' çalıştır veya -no-nuclei kullan")
	}
	if msg != "" {
		return fmt.Errorf("nuclei hata: %v: %s", err, msg)
	}
	return fmt.Errorf("nuclei hata: %w", err)
}

func nucleiTemplatesDir() string {
	candidates := []string{
		strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATES")),
		strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATES_PATH")),
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, "nuclei-templates"),
			filepath.Join(home, ".local", "nuclei-templates"),
			filepath.Join(home, ".config", "nuclei", "templates"),
			filepath.Join(home, ".config", "nuclei", "nuclei-templates"),
		)
	}
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir
		}
	}
	return ""
}

// FIX: GAUTimeout artık profile'a göre (stealth=60s, balanced=180s, fast=120s)
func runGAU(ctx context.Context, target string, gauTimeout time.Duration, rules []string, warnings *[]string) []string {
	if _, err := exec.LookPath("gau"); err != nil {
		*warnings = append(*warnings, "gau yok; wayback/commoncrawl pasif URL toplama atlandı")
		return nil
	}
	tCtx, cancel := context.WithTimeout(ctx, gauTimeout)
	defer cancel()
	cmd := exec.CommandContext(tCtx, "gau", "--subs", target)
	out, err := cmd.Output()
	if tCtx.Err() == context.DeadlineExceeded {
		*warnings = append(*warnings, fmt.Sprintf("gau timeout (%s); kısmi/boş sonuç kullanıldı", gauTimeout))
		return nil
	}
	if err != nil {
		*warnings = append(*warnings, "gau çalıştırılamadı: "+err.Error())
		return nil
	}
	lines := strings.Split(string(out), "\n")
	return safety.FilterSafeScopedURLs(lines, rules)
}

// ── HTTP yardımcıları ────────────────────────────────────────────────────────

func fallbackLive(ctx context.Context, hosts []string, p Profile, rules []string, client *http.Client) []string {
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := []string{}

	for _, h := range hosts {
		for _, scheme := range []string{"https://", "http://"} {
			u := scheme + h
			if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
				continue
			}
			wg.Add(1)
			go guarded(func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				lim.wait()

				select {
				case <-ctx.Done():
					return
				default:
				}

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					return
				}
				researchheaders.Apply(req)
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode < 500 {
					mu.Lock()
					out = append(out, u)
					mu.Unlock()
				}
			})
		}
	}
	wg.Wait()
	return uniq(out)
}

func passiveURLs(ctx context.Context, target string, live []string, p Profile, rules []string, noGAU bool, warnings *[]string, client *http.Client) []string {
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := []string{}

	if !noGAU {
		out = append(out, runGAU(ctx, target, p.GAUTimeout, rules, warnings)...)
	}

	for _, base := range live {
		for _, path := range []string{"robots.txt", "sitemap.xml"} {
			u := strings.TrimRight(base, "/") + "/" + path
			if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
				continue
			}
			wg.Add(1)
			go guarded(func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				lim.wait()

				select {
				case <-ctx.Done():
					return
				default:
				}

				body, ok := fetchTextWithContext(ctx, client, u)
				if !ok {
					return
				}
				mu.Lock()
				out = append(out, safety.FilterSafeScopedURLs(extractURLs(body), rules)...)
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	return uniq(out)
}

func jsAndEndpoints(ctx context.Context, live, passive []string, p Profile, rules []string, client *http.Client) ([]string, []string) {
	candidates := safety.FilterSafeScopedURLs(append(append([]string{}, passive...), live...), rules)
	js, eps := fetchJSAndEndpoints(ctx, candidates, p, rules, client)
	if len(js) > 0 {
		js2, eps2 := fetchJSAndEndpoints(ctx, js, p, rules, client)
		js = append(js, js2...)
		eps = append(eps, eps2...)
	}
	return uniq(safety.FilterSafeScopedURLs(js, rules)), uniq(eps)
}

func fetchJSAndEndpoints(ctx context.Context, candidates []string, p Profile, rules []string, client *http.Client) ([]string, []string) {
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	js, eps := []string{}, []string{}

	for _, u := range uniq(candidates) {
		if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
			continue
		}
		wg.Add(1)
		go guarded(func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lim.wait()

			select {
			case <-ctx.Done():
				return
			default:
			}

			body, ok := fetchTextWithContext(ctx, client, u)
			if !ok {
				return
			}
			body = html.UnescapeString(body)
			localJS := safety.FilterSafeScopedURLs(extractJS(u, body), rules)
			localEP := extractEndpoints(body)
			if strings.HasSuffix(strings.ToLower(u), ".js") {
				localJS = append(localJS, u)
			}
			mu.Lock()
			js = append(js, localJS...)
			eps = append(eps, localEP...)
			mu.Unlock()
		})
	}
	wg.Wait()
	return uniq(js), uniq(eps)
}

func probeEndpoints(ctx context.Context, live, endpoints []string, p Profile, rules []string, client *http.Client) []EndpointProbe {
	targets := endpointProbeTargets(live, endpoints, rules)
	if len(targets) == 0 {
		return nil
	}
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]EndpointProbe, 0, len(targets))

	for endpoint, u := range targets {
		endpoint, u := endpoint, u
		wg.Add(1)
		go guarded(func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lim.wait()

			select {
			case <-ctx.Done():
				return
			default:
			}

			probe := probeEndpoint(ctx, client, endpoint, u)
			mu.Lock()
			out = append(out, probe)
			mu.Unlock()
		})
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func endpointProbeTargets(live, endpoints, rules []string) map[string]string {
	out := map[string]string{}
	for _, endpoint := range uniq(endpoints) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
			if safety.IsSafeFetchURL(endpoint) && safety.ScopeAllowsURL(endpoint, rules) {
				out[endpoint] = endpoint
			}
			continue
		}
		if !strings.HasPrefix(endpoint, "/") {
			continue
		}
		for _, base := range live {
			u := strings.TrimRight(base, "/") + endpoint
			if safety.IsSafeFetchURL(u) && safety.ScopeAllowsURL(u, rules) {
				out[endpoint] = u
			}
		}
	}
	return out
}

func probeEndpoint(ctx context.Context, client *http.Client, endpoint, u string) EndpointProbe {
	probe := EndpointProbe{Endpoint: endpoint, URL: u}
	head := endpointRequest(ctx, client, http.MethodHead, u, 0)
	get := endpointRequest(ctx, client, http.MethodGet, u, 64_000)
	options := endpointRequest(ctx, client, http.MethodOptions, u, 0)

	probe.HEADStatus = head.Status
	probe.GETStatus = get.Status
	probe.OPTIONSStatus = options.Status
	probe.ContentType = get.ContentType
	probe.Size = get.Size
	probe.Allow = firstNonEmptyString(options.Allow, head.Allow, get.Allow)
	probe.CORSAllowOrigin = firstNonEmptyString(options.CORSAllowOrigin, head.CORSAllowOrigin, get.CORSAllowOrigin)
	probe.Classification, probe.Note = classifyEndpointProbe(get, options)
	probe.SensitiveFields = classifySensitiveFields(get.Body, get.ContentType)
	probe.RiskScore, probe.Risk = sensitiveFieldRisk(probe.SensitiveFields)
	if probe.RiskScore > 0 {
		if probe.Classification == "public_json" {
			probe.Classification = "public_json_sensitive"
		}
		probe.Note = strings.TrimSpace(probe.Note + "; sensitive field risk " + probe.Risk + "/" + fmt.Sprint(probe.RiskScore) + ": " + summarizeSensitiveFields(probe.SensitiveFields))
	}
	return probe
}

type endpointResponse struct {
	Status          int
	ContentType     string
	Size            int64
	Allow           string
	CORSAllowOrigin string
	Body            []byte
	Err             error
}

func endpointRequest(ctx context.Context, client *http.Client, method, u string, bodyLimit int64) endpointResponse {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return endpointResponse{Err: err}
	}
	researchheaders.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return endpointResponse{Err: err}
	}
	defer resp.Body.Close()
	size := resp.ContentLength
	if bodyLimit > 0 && resp.Body != nil {
		b, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		if err == nil && size < 0 {
			size = int64(len(b))
		}
		if err == nil {
			return endpointResponse{
				Status:          resp.StatusCode,
				ContentType:     resp.Header.Get("Content-Type"),
				Size:            size,
				Allow:           resp.Header.Get("Allow"),
				CORSAllowOrigin: resp.Header.Get("Access-Control-Allow-Origin"),
				Body:            b,
			}
		}
	}
	return endpointResponse{
		Status:          resp.StatusCode,
		ContentType:     resp.Header.Get("Content-Type"),
		Size:            size,
		Allow:           resp.Header.Get("Allow"),
		CORSAllowOrigin: resp.Header.Get("Access-Control-Allow-Origin"),
	}
}

func classifyEndpointProbe(get, options endpointResponse) (string, string) {
	if get.Err != nil {
		return "error", "request failed: " + get.Err.Error()
	}
	switch {
	case get.Status == 401:
		return "auth_required", "authentication required"
	case get.Status == 403:
		return "forbidden", "access denied without authorization"
	case get.Status == 404:
		return "not_found", "endpoint candidate not found"
	case get.Status == 405:
		return "method_not_allowed", "GET is not allowed; review allowed methods"
	case get.Status == 429:
		return "rate_limited", "rate limited; do not continue aggressive probing"
	case get.Status >= 500:
		return "server_error", "server returned an error"
	case get.Status >= 300 && get.Status < 400:
		return "redirect", "endpoint redirects"
	case get.Status >= 200 && get.Status < 300:
		ct := strings.ToLower(get.ContentType)
		if strings.Contains(ct, "json") {
			return "public_json", "unauthenticated JSON response; review for sensitive data exposure"
		}
		if strings.Contains(ct, "html") {
			return "public_html", "unauthenticated HTML response"
		}
		if get.Status == 204 || get.Size == 0 {
			return "public_empty", "successful empty response"
		}
		return "public_response", "unauthenticated response"
	default:
		if options.Status > 0 {
			return "options_only", "OPTIONS responded; main method inconclusive"
		}
		return "unknown", "endpoint behavior inconclusive"
	}
}

func endpointProbeFindings(probes []EndpointProbe) []Finding {
	out := []Finding{}
	for _, p := range probes {
		if p.RiskScore > 0 && (p.Classification == "public_json_sensitive" || p.Classification == "public_json") {
			conf := "medium"
			if p.Risk == "high" {
				conf = "high"
			}
			out = append(out, Finding{
				Type:       "public_api_sensitive_fields",
				URL:        p.URL,
				Status:     p.GETStatus,
				Confidence: conf,
				Note:       fmt.Sprintf("unauthenticated JSON exposes sensitive-looking fields (%s/%d): %s", p.Risk, p.RiskScore, summarizeSensitiveFields(p.SensitiveFields)),
			})
			continue
		}
		switch p.Classification {
		case "public_json":
			out = append(out, Finding{
				Type:       "public_api_json",
				URL:        p.URL,
				Status:     p.GETStatus,
				Confidence: "medium",
				Note:       "unauthenticated JSON response; review for data exposure or missing authorization",
			})
		case "auth_required":
			out = append(out, Finding{
				Type:       "auth_required_api",
				URL:        p.URL,
				Status:     p.GETStatus,
				Confidence: "info",
				Note:       "endpoint exists and requires authentication",
			})
		case "method_not_allowed":
			out = append(out, Finding{
				Type:       "api_method_probe",
				URL:        p.URL,
				Status:     p.GETStatus,
				Confidence: "info",
				Note:       "endpoint exists but GET is not allowed",
			})
		}
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func discover(ctx context.Context, live, paths []string, p Profile, rules []string, client *http.Client) []Finding {
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := []Finding{}

	for _, base := range live {
		soft404, hasSoft404 := soft404Baseline(ctx, client, base, rules)
		for _, path := range paths {
			path = strings.TrimSpace(path)
			if path == "" || strings.HasPrefix(path, "#") {
				continue
			}
			u := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
			if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
				continue
			}
			wg.Add(1)
			go guarded(func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				lim.wait()

				select {
				case <-ctx.Done():
					return
				default:
				}

				sample, ok := fetchSample(ctx, client, u)
				if !ok {
					return
				}
				if hasSoft404 && looksLikeSoft404(sample, soft404) {
					return
				}
				if sample.Status == 200 || sample.Status == 401 ||
					sample.Status == 403 || sample.Status == 301 || sample.Status == 302 {
					mu.Lock()
					out = append(out, Finding{classifyPath(path), u, sample.Status, confidence(sample.Status), "manuel inceleme adayı"})
					mu.Unlock()
				}
			})
		}
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

type responseSample struct {
	Status      int
	ContentType string
	Title       string
	Body        string
}

func soft404Baseline(ctx context.Context, client *http.Client, base string, rules []string) (responseSample, bool) {
	u := strings.TrimRight(base, "/") + "/.reconixia-soft404-check-" + fmt.Sprint(time.Now().UnixNano())
	if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
		return responseSample{}, false
	}
	sample, ok := fetchSample(ctx, client, u)
	if !ok {
		return responseSample{}, false
	}
	return sample, sample.Status == 200 && isHTML(sample.ContentType) && isNotFoundHTML(sample)
}

func fetchSample(ctx context.Context, client *http.Client, u string) (responseSample, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return responseSample{}, false
	}
	researchheaders.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return responseSample{}, false
	}
	defer resp.Body.Close()
	body := ""
	if resp.Body != nil {
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256_000))
		if err == nil {
			body = string(b)
		}
	}
	return responseSample{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Title:       pageTitle(body),
		Body:        body,
	}, true
}

func looksLikeSoft404(candidate, baseline responseSample) bool {
	if candidate.Status != 200 || baseline.Status != 200 {
		return false
	}
	if !isHTML(candidate.ContentType) || !isHTML(baseline.ContentType) {
		return false
	}
	if candidate.Title != "" && baseline.Title != "" && strings.EqualFold(candidate.Title, baseline.Title) {
		return true
	}
	return isNotFoundHTML(candidate) && isNotFoundHTML(baseline)
}

func isHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

func isNotFoundHTML(sample responseSample) bool {
	body := strings.ToLower(sample.Body)
	title := strings.ToLower(sample.Title)
	return strings.Contains(title, "not found") ||
		strings.Contains(body, "rel=\"canonical\"") && strings.Contains(body, "/404") ||
		strings.Contains(body, "<title>404") ||
		strings.Contains(body, "page not found")
}

// fetchText — context destekli versiyon
func fetchTextWithContext(ctx context.Context, client *http.Client, u string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	researchheaders.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4_000_000)) // FIX: 2MB → 4MB
	if err != nil {
		return "", false
	}
	return string(b), true
}

// fetchText — context'siz geriye dönük compat
func fetchText(client *http.Client, u string) (string, bool) {
	return fetchTextWithContext(context.Background(), client, u)
}

// FIX: guarded() artık panikleri logluyor — sessiz kayıp yok
func guarded(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[WARN] goroutine panic yakalandı: %v", r)
		}
	}()
	fn()
}

// ── AI analiz ────────────────────────────────────────────────────────────────

// Setup / Doctor
