package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/headers"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
	"github.com/Veyselyigit21/Reconixia/internal/secrets"
	"github.com/Veyselyigit21/Reconixia/internal/takeover"
)

// ── Tipler ──────────────────────────────────────────────────────────────────

type Profile struct {
	Name    string        `json:"name"`
	Rate    int           `json:"rate_per_second"`
	Threads int           `json:"threads"`
	Timeout time.Duration `json:"-"`
	GAUTimeout time.Duration `json:"-"`
}

type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

type Report struct {
	Target       string    `json:"target"`
	Profile      Profile   `json:"profile"`
	GeneratedAt  string    `json:"generated_at"`
	Subdomains   []string  `json:"subdomains"`
	LiveHosts    []string  `json:"live_hosts"`
	PassiveURLs  []string  `json:"passive_urls"`
	JSFiles      []string  `json:"js_files"`
	Endpoints    []string  `json:"endpoints"`
	Findings     []Finding `json:"findings"`
	Warnings     []string  `json:"warnings"`
	ExportTarget string    `json:"export_target"`
}

type Options struct {
	Target    string
	ScopeFile string
	Profile   string
	Wordlist  string
	NoNuclei  bool
	Severity  string
	NoGAU     bool
	NoHeaders bool
}

type limiter struct{ tick <-chan time.Time }

func newLimiter(rate int) *limiter {
	if rate < 1 {
		rate = 1
	}
	return &limiter{tick: time.Tick(time.Second / time.Duration(rate))}
}

func (l *limiter) wait() { <-l.tick }

// ── Entry point ──────────────────────────────────────────────────────────────

func main() {
	loadEnv()
	if len(os.Args) == 1 {
		menu()
		return
	}
	switch os.Args[1] {
	case "setup", "keys":
		setup()
	case "doctor":
		doctor()
	case "run":
		cmdRun(os.Args[2:])
	case "analyze":
		cmdAnalyze(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Reconixia v0.6")
	fmt.Println("  reconixia")
	fmt.Println("  reconixia setup")
	fmt.Println("  reconixia doctor")
	fmt.Println("  reconixia run -target hedef.com [-scope scope.txt] [-profile balanced] [-severity info,low,medium] [-no-gau] [-no-headers]")
	fmt.Println("  reconixia analyze -target hedef.com [-provider local]")
}

func menu() {
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nReconixia v0.6 Ana Menü")
		fmt.Println("1) Local recon başlat")
		fmt.Println("2) AI analiz yap")
		fmt.Println("3) Setup / API key yönetimi")
		fmt.Println("4) Doctor / sistem kontrolü")
		fmt.Println("0) Çıkış")
		switch ask(in, "Seçim", "") {
		case "1":
			t := ask(in, "Hedef domain", "")
			p := ask(in, "Profil [stealth/balanced/fast]", "balanced")
			s := ask(in, "Scope dosyası", "")
			w := ask(in, "Wordlist", "")
			_, err := run(context.Background(), Options{Target: t, Profile: p, ScopeFile: s, Wordlist: w, Severity: "info,low,medium"})
			if err != nil {
				fmt.Println("Hata:", err)
			}
		case "2":
			t := ask(in, "Hedef", "")
			provider := ask(in, "Provider", getenv("RECONIXIA_AI_PROVIDER", "local"))
			model := ask(in, "Model", "")
			if err := analyze(t, provider, model); err != nil {
				fmt.Println("Hata:", err)
			}
		case "3":
			setup()
		case "4":
			doctor()
		case "0":
			return
		default:
			fmt.Println("Geçersiz seçim")
		}
	}
}

// ── run komutu ───────────────────────────────────────────────────────────────

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	target := fs.String("target", "", "hedef domain")
	scope := fs.String("scope", "", "scope dosyası")
	prof := fs.String("profile", "balanced", "stealth|balanced|fast")
	wordlist := fs.String("wordlist", "", "wordlist dosyası")
	noNuclei := fs.Bool("no-nuclei", false, "nuclei taramasını atla")
	severity := fs.String("severity", "", "nuclei severity override")
	noGAU := fs.Bool("no-gau", false, "gau/wayback pasif URL modülünü atla")
	noHeaders := fs.Bool("no-headers", false, "CORS/security header analizini atla")
	_ = fs.Parse(args)

	if *target == "" {
		fatal("target gerekli")
	}

	// Sinyal ile iptal edilebilir context — FIX: graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	_, err := run(ctx, Options{
		Target:    *target,
		ScopeFile: *scope,
		Profile:   *prof,
		Wordlist:  *wordlist,
		NoNuclei:  *noNuclei,
		Severity:  *severity,
		NoGAU:     *noGAU,
		NoHeaders: *noHeaders,
	})
	if err != nil {
		fatal(err.Error())
	}
}

// ── Ana tarama akışı ─────────────────────────────────────────────────────────

func run(ctx context.Context, o Options) (*Report, error) {
	target, ok := safety.NormalizeTarget(o.Target)
	if !ok {
		return nil, fmt.Errorf("geçersiz veya güvenli olmayan hedef: %q", o.Target)
	}

	p := profile(o.Profile)
	if o.Severity == "" {
		o.Severity = defaultSeverity(p.Name)
	}

	ws := filepath.Join("results", target)
	// FIX: workspace dizinleri 0700 (sadece sahibi okuyabilir)
	for _, d := range []string{"raw", "processed", "export", "logs"} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0700); err != nil {
			log.Printf("[WARN] dizin oluşturulamadı: %v", err)
		}
	}

	warnings := []string{}
	scopeRules := loadScope(o.ScopeFile, target, &warnings)

	// HTTP client — FIX: DNS rebinding korumalı SafeHTTPClient
	client := safety.SafeHTTPClient(p.Timeout)

	fmt.Println("[1/9] Alt alan adı keşfi")
	subs, err := subfinder(target, filepath.Join(ws, "raw", "subdomains.txt"))
	if err != nil {
		warnings = append(warnings, err.Error())
	}
	if len(subs) == 0 {
		subs = []string{target}
	}
	subs = filterHostsByScope(subs, scopeRules)
	writeLines(filepath.Join(ws, "raw", "subdomains.txt"), subs)

	fmt.Println("[2/9] Canlı hedef kontrolü")
	live, err := httpxLive(filepath.Join(ws, "raw", "subdomains.txt"), filepath.Join(ws, "processed", "live_hosts.txt"), p)
	if err != nil {
		warnings = append(warnings, err.Error())
	}
	if len(live) == 0 {
		live = fallbackLive(ctx, subs, p, scopeRules, client)
	}
	live = safety.FilterSafeScopedURLs(live, scopeRules)
	writeLines(filepath.Join(ws, "processed", "live_hosts.txt"), live)
	writeLines(filepath.Join(ws, "export", "targets.txt"), live)

	fmt.Println("[3/9] Pasif URL toplama")
	passive := passiveURLs(ctx, target, live, p, scopeRules, o.NoGAU, &warnings, client)
	writeLines(filepath.Join(ws, "processed", "passive_urls.txt"), passive)

	fmt.Println("[4/9] JS ve endpoint çıkarımı")
	js, endpoints := jsAndEndpoints(ctx, live, passive, p, scopeRules, client)
	writeLines(filepath.Join(ws, "processed", "js_files.txt"), js)
	writeLines(filepath.Join(ws, "processed", "endpoints.txt"), endpoints)

	fmt.Println("[5/9] İlginç path keşfi")
	findings := discover(ctx, live, loadWordlist(o.Wordlist), p, scopeRules, client)
	findings = append(findings, classifyEndpoints(endpoints)...)
	// FIX: internal/secrets paketi kullanılıyor (8 → 11 pattern)
	findings = append(findings, secretScan(ctx, js, p, scopeRules, client)...)

	fmt.Println("[6/9] CORS ve Security Header analizi")
	if o.NoHeaders {
		warnings = append(warnings, "header analizi kullanıcı tercihiyle atlandı")
	} else {
		findings = append(findings, analyzeHeaders(live, p, scopeRules, client)...)
	}
	writeFindings(filepath.Join(ws, "processed", "interesting_paths.txt"), findings)

	fmt.Println("[7/9] Nuclei safe scan")
	if o.NoNuclei {
		warnings = append(warnings, "nuclei kullanıcı tercihiyle atlandı")
	} else if err := nuclei(filepath.Join(ws, "export", "targets.txt"), filepath.Join(ws, "processed", "nuclei_safe.txt"), p, o.Severity); err != nil {
		warnings = append(warnings, err.Error())
	}

	// FIX: Subdomain takeover artık ana akışta (adım 8)
	fmt.Println("[8/9] Subdomain takeover ön analizi")
	for _, tf := range takeover.AnalyzeSubdomains(subs, scopeRules) {
		findings = append(findings, Finding{
			Type:       tf.Type,
			URL:        tf.URL,
			Status:     tf.Status,
			Confidence: tf.Confidence,
			Note:       tf.Note,
		})
	}

	fmt.Println("[9/9] Rapor")
	report := &Report{
		Target:       target,
		Profile:      p,
		GeneratedAt:  time.Now().Format(time.RFC3339),
		Subdomains:   subs,
		LiveHosts:    live,
		PassiveURLs:  passive,
		JSFiles:      js,
		Endpoints:    endpoints,
		Findings:     deduplicateFindings(findings),
		Warnings:     warnings,
		ExportTarget: filepath.Join(ws, "export", "targets.txt"),
	}
	writeReport(ws, *report)
	fmt.Println("Tamamlandı:", ws)
	return report, nil
}

// ── Header analizi ───────────────────────────────────────────────────────────

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

func httpxLive(in, out string, p Profile) ([]string, error) {
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx yok; internal fallback kullanılacak")
	}
	cmd := exec.Command("httpx",
		"-l", in,
		"-silent",
		"-follow-host-redirects",
		"-status-code",
		"-title",
		"-tech-detect",
		"-rate-limit", fmt.Sprint(p.Rate),
		"-threads", fmt.Sprint(p.Threads),
		"-o", out,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	lines, _ := readLines(out)
	return firstURL(lines), nil
}

func nuclei(in, out string, p Profile, severity string) error {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return fmt.Errorf("nuclei yok; atlandı")
	}
	cmd := exec.Command("nuclei",
		"-l", in,
		"-severity", severity,
		"-rate-limit", fmt.Sprint(p.Rate),
		"-silent",
		"-o", out,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
				req.Header.Set("User-Agent", "Reconixia/1.0 AuthorizedResearch")
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

func discover(ctx context.Context, live, paths []string, p Profile, rules []string, client *http.Client) []Finding {
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := []Finding{}

	for _, base := range live {
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

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Reconixia/1.0 AuthorizedResearch")
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode == 200 || resp.StatusCode == 401 ||
					resp.StatusCode == 403 || resp.StatusCode == 301 || resp.StatusCode == 302 {
					mu.Lock()
					out = append(out, Finding{classifyPath(path), u, resp.StatusCode, confidence(resp.StatusCode), "manuel inceleme adayı"})
					mu.Unlock()
				}
			})
		}
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// fetchText — context destekli versiyon
func fetchTextWithContext(ctx context.Context, client *http.Client, u string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "Reconixia/1.0 AuthorizedResearch")
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

func cmdAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	target := fs.String("target", "", "")
	provider := fs.String("provider", getenv("RECONIXIA_AI_PROVIDER", "local"), "")
	model := fs.String("model", "", "")
	_ = fs.Parse(args)
	if *target == "" {
		fatal("target gerekli")
	}
	if err := analyze(*target, *provider, *model); err != nil {
		fatal(err.Error())
	}
}

func analyze(target, provider, model string) error {
	t, ok := safety.NormalizeTarget(target)
	if !ok {
		return fmt.Errorf("geçersiz hedef")
	}
	raw, err := os.ReadFile(filepath.Join("results", t, "report.md"))
	if err != nil {
		return fmt.Errorf("önce recon çalıştırılmalı")
	}
	// FIX: rapor çok büyükse token limitini aşmamak için kırp
	reportText := string(raw)
	const maxChars = 80_000
	if len(reportText) > maxChars {
		reportText = reportText[:maxChars] + "\n\n[... rapor token limiti nedeniyle kırpıldı ...]"
	}
	out, err := askAI(provider, model, reportText)
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join("results", t, "ai_analysis.md"), []byte(out), 0600)
	fmt.Println(out)
	return nil
}

func askAI(provider, model, report string) (string, error) {
	provider = strings.ToLower(provider)
	if provider == "local" {
		return localAnalysis(report), nil
	}
	if model == "" {
		model = defaultModel(provider)
	}
	sys := "Analyze authorized bug bounty recon output. Prioritize API, IDOR, information disclosure and business logic review targets. Do not provide exploitation instructions."
	switch provider {
	case "openrouter":
		return askOpenAI("https://openrouter.ai/api/v1/chat/completions", os.Getenv("OPENROUTER_API_KEY"), model, sys, report)
	case "openai":
		return askOpenAI("https://api.openai.com/v1/chat/completions", os.Getenv("OPENAI_API_KEY"), model, sys, report)
	case "deepseek":
		return askOpenAI("https://api.deepseek.com/chat/completions", os.Getenv("DEEPSEEK_API_KEY"), model, sys, report)
	default:
		return "", fmt.Errorf("bilinmeyen provider")
	}
}

// FIX: retry mekanizması eklendi (429 ve 503 için exponential backoff)
func askOpenAI(endpoint, key, model, sys, user string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("API key yok")
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": sys},
			{"role": "user", "content": user},
		},
	}
	raw, _ := json.Marshal(payload)

	httpClient := &http.Client{Timeout: 60 * time.Second}
	var lastErr error
	backoff := 2 * time.Second

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			lastErr = fmt.Errorf("HTTP %d: rate limit / servis dışı, tekrar denenecek", resp.StatusCode)
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4_000_000))
		var parsed struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if json.Unmarshal(body, &parsed) == nil && len(parsed.Choices) > 0 {
			return parsed.Choices[0].Message.Content, nil
		}
		return string(body), nil
	}
	return "", fmt.Errorf("AI API başarısız (3 deneme): %v", lastErr)
}

func defaultModel(p string) string {
	switch p {
	case "openai":
		return getenv("OPENAI_MODEL", "gpt-4o-mini")
	case "deepseek":
		return getenv("DEEPSEEK_MODEL", "deepseek-reasoner")
	default:
		return getenv("OPENROUTER_MODEL", "deepseek/deepseek-r1")
	}
}

func localAnalysis(report string) string {
	var b strings.Builder
	b.WriteString("# Reconixia Yerel Analiz\n\n")
	for _, line := range strings.Split(report, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "api") || strings.Contains(l, "swagger") ||
			strings.Contains(l, "graphql") || strings.Contains(l, "admin") ||
			strings.Contains(l, "login") || strings.Contains(l, "idor") {
			b.WriteString("- " + line + "\n")
		}
	}
	return b.String()
}

// ── Setup / Doctor ───────────────────────────────────────────────────────────

func setup() {
	in := bufio.NewReader(os.Stdin)
	env := readEnv()
	for {
		fmt.Println("\nReconixia Kurulum Menüsü")
		fmt.Println("1) AI sağlayıcısı / model / API key ayarla")
		fmt.Println("2) Kayıtlı ayarları göster")
		fmt.Println("3) Kaydet ve çık")
		fmt.Println("0) Çıkış")
		switch ask(in, "Seçim", "") {
		case "1":
			setupAI(in, env)
		case "2":
			printEnv(env)
		case "3":
			writeEnv(env)
			return
		case "0":
			return
		}
	}
}

func setupAI(in *bufio.Reader, env map[string]string) {
	fmt.Println("1) Local\n2) OpenRouter\n3) OpenAI\n4) DeepSeek\n0) Geri")
	switch ask(in, "Seçim", "") {
	case "1":
		env["RECONIXIA_AI_PROVIDER"] = "local"
	case "2":
		env["RECONIXIA_AI_PROVIDER"] = "openrouter"
		askSecret(in, env, "OPENROUTER_API_KEY", "OpenRouter key")
		askValue(in, env, "OPENROUTER_MODEL", "Model", "deepseek/deepseek-r1")
	case "3":
		env["RECONIXIA_AI_PROVIDER"] = "openai"
		askSecret(in, env, "OPENAI_API_KEY", "OpenAI key")
		askValue(in, env, "OPENAI_MODEL", "Model", "gpt-4o-mini")
	case "4":
		env["RECONIXIA_AI_PROVIDER"] = "deepseek"
		askSecret(in, env, "DEEPSEEK_API_KEY", "DeepSeek key")
		askValue(in, env, "DEEPSEEK_MODEL", "Model", "deepseek-reasoner")
	}
}

func loadEnv() {
	for k, v := range readEnv() {
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

func readEnv() map[string]string {
	m := map[string]string{
		"RECONIXIA_AI_PROVIDER": "local",
		"OPENROUTER_MODEL":      "deepseek/deepseek-r1",
		"OPENAI_MODEL":          "gpt-4o-mini",
		"DEEPSEEK_MODEL":        "deepseek-reasoner",
	}
	f, err := os.Open(".env")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		m[strings.TrimSpace(p[0])] = strings.Trim(strings.TrimSpace(p[1]), "\"")
	}
	return m
}

func writeEnv(m map[string]string) {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	// FIX: Uyarı mesajı düzeltildi
	b.WriteString("# Reconixia configuration\n")
	b.WriteString("# UYARI: Bu dosyayı GitHub'a veya herhangi bir repo'ya YUKLEMEYİN — API key içerir!\n\n")
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + "\n")
	}
	if err := os.WriteFile(".env", []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] .env yazılamadı: %v", err)
		return
	}
	loadEnv()
	fmt.Println("Ayarlar kaydedildi: .env")
}

func printEnv(m map[string]string) {
	for _, k := range []string{"RECONIXIA_AI_PROVIDER", "OPENROUTER_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"} {
		v := m[k]
		if strings.Contains(k, "KEY") {
			v = mask(v)
		}
		if v == "" {
			v = "boş"
		}
		fmt.Println(k, "=", v)
	}
}

func mask(s string) string {
	if s == "" {
		return "boş"
	}
	if len(s) < 9 {
		return "********"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func askSecret(in *bufio.Reader, m map[string]string, k, label string) {
	v := ask(in, label+" ["+mask(m[k])+"]", "")
	if v != "" {
		m[k] = v
	}
}

func askValue(in *bufio.Reader, m map[string]string, k, label, def string) {
	if m[k] != "" {
		def = m[k]
	}
	v := ask(in, label, def)
	if v != "" {
		m[k] = v
	}
}

func doctor() {
	for _, b := range []string{"go", "git", "subfinder", "httpx", "nuclei", "gau"} {
		if _, err := exec.LookPath(b); err == nil {
			fmt.Println("[OK]", b)
		} else {
			fmt.Println("[YOK]", b)
		}
	}
	for _, e := range []string{"OPENROUTER_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"} {
		if os.Getenv(e) != "" {
			fmt.Println("[OK]", e)
		} else {
			fmt.Println("[YOK]", e, "(opsiyonel)")
		}
	}
}

// ── Wordlist / dosya yardımcıları ────────────────────────────────────────────

func loadWordlist(path string) []string {
	for _, p := range []string{path, "wordlists/interesting_paths.txt"} {
		if p != "" {
			if l, err := readLines(p); err == nil && len(l) > 0 {
				return l
			}
		}
	}
	return []string{
		"admin", "login", "dashboard", "panel",
		"api", "api/v1", "api/v2", "api/v3",
		"graphql", "swagger", "swagger-ui", "openapi.json", "openapi.yaml",
		"robots.txt", "sitemap.xml", "health", "status", "config",
		".git/config", ".env", "backup", "phpinfo.php",
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// FIX: Yazma hataları artık loglanıyor (sessiz disk-dolu senaryosu önlendi)
func writeLines(path string, lines []string) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("[WARN] dizin oluşturulamadı %s: %v", filepath.Dir(path), err)
		return
	}
	if err := os.WriteFile(path, []byte(strings.Join(uniq(lines), "\n")+"\n"), 0600); err != nil {
		log.Printf("[WARN] dosya yazılamadı %s: %v", path, err)
	}
}

func writeFindings(path string, fs []Finding) {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(fmt.Sprintf("%s | %d | %s | %s | %s\n", f.URL, f.Status, f.Type, f.Confidence, f.Note))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] findings yazılamadı: %v", err)
	}
}

func writeReport(ws string, r Report) {
	raw, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(ws, "report.json"), raw, 0600); err != nil {
		log.Printf("[WARN] report.json yazılamadı: %v", err)
	}
	var b strings.Builder
	b.WriteString("# Reconixia Raporu\n\n")
	b.WriteString("Hedef: `" + r.Target + "`\n\n")
	b.WriteString(fmt.Sprintf("Profil: `%s` | Rate: `%d/sn` | Threads: `%d`\n\n", r.Profile.Name, r.Profile.Rate, r.Profile.Threads))
	b.WriteString(fmt.Sprintf("Alt alan adı: **%d**  \nCanlı hedef: **%d**  \nPasif URL: **%d**  \nJS: **%d**  \nEndpoint: **%d**  \nBulgu: **%d**\n\n",
		len(r.Subdomains), len(r.LiveHosts), len(r.PassiveURLs), len(r.JSFiles), len(r.Endpoints), len(r.Findings)))
	if len(r.Warnings) > 0 {
		b.WriteString("## Uyarılar\n\n")
		for _, w := range r.Warnings {
			b.WriteString("- " + w + "\n")
		}
	}
	b.WriteString("\n## Öncelikli Bulgular\n\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("- `%s` [%d] %s / %s — %s\n", f.URL, f.Status, f.Type, f.Confidence, f.Note))
	}
	if err := os.WriteFile(filepath.Join(ws, "report.md"), []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] report.md yazılamadı: %v", err)
	}
}

// ── Parse yardımcıları ───────────────────────────────────────────────────────

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

func ask(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	t, _ := in.ReadString('\n')
	t = strings.TrimSpace(t)
	if t == "" {
		return def
	}
	return t
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(s string) {
	fmt.Fprintln(os.Stderr, "hata:", s)
	os.Exit(1)
}
