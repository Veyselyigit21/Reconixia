package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/Veyselyigit21/Reconixia/internal/researchheaders"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
	"github.com/Veyselyigit21/Reconixia/internal/webchecks"
)

// webToFindings converts webchecks.Finding values into the host Finding type.
func webToFindings(in []webchecks.Finding) []Finding {
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		out = append(out, Finding{Type: f.Type, URL: f.URL, Status: f.Status, Confidence: f.Confidence, Note: f.Note})
	}
	return out
}

// researchHeaderArg returns a "Name: value" header string for external tools
// (katana/arjun) when a research attribution header is configured, else "".
func researchHeaderArg() string {
	name := strings.TrimSpace(os.Getenv("RECONIXIA_RESEARCH_HEADER_NAME"))
	if name == "" {
		name = "X-HackerOne-Research"
	}
	value := strings.TrimSpace(os.Getenv("RECONIXIA_RESEARCH_HEADER_VALUE"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("RECONIXIA_H1_USERNAME"))
	}
	if value == "" {
		return ""
	}
	return name + ": " + value
}

// writeTempList writes lines to a temp file and returns its path plus a cleanup
// func. Used to feed URL lists to external tools.
func writeTempList(lines []string) (string, func(), error) {
	f, err := os.CreateTemp("", "reconixia-list-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	_, _ = f.WriteString(strings.Join(lines, "\n") + "\n")
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

// runKatana performs an active crawl of the live hosts with katana, merging the
// discovered (in-scope, safe) URLs back into the passive corpus. Opt-in: it
// sends traffic to the target, so the caller gates it behind -katana.
func runKatana(ctx context.Context, inputFile string, p Profile, rules []string, warnings *[]string) []string {
	if _, err := exec.LookPath("katana"); err != nil {
		*warnings = append(*warnings, "katana yok; derin crawl atlandı (go install .../katana@latest)")
		return nil
	}
	depth := "2"
	if p.Name == "fast" {
		depth = "3"
	} else if p.Name == "stealth" {
		depth = "1"
	}
	args := []string{
		"-list", inputFile,
		"-silent",
		"-jc",       // crawl endpoints referenced from JavaScript
		"-d", depth, // crawl depth
		"-c", fmt.Sprint(p.Threads),
		"-rl", fmt.Sprint(p.Rate),
		"-timeout", fmt.Sprint(int(p.Timeout.Seconds())),
		"-fs", "fqdn", // keep the crawl on the seed hosts
	}
	if h := researchHeaderArg(); h != "" {
		args = append(args, "-H", h)
	}
	runCtx, cancel := context.WithTimeout(ctx, p.GAUTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "katana", args...)
	out, err := cmd.Output()
	if runCtx.Err() == context.DeadlineExceeded {
		*warnings = append(*warnings, fmt.Sprintf("katana timeout (%s); kısmi sonuç kullanıldı", p.GAUTimeout))
	} else if err != nil {
		*warnings = append(*warnings, "katana çalıştırılamadı: "+err.Error())
		return nil
	}
	lines := strings.Split(string(out), "\n")
	return safety.FilterSafeScopedURLs(lines, rules)
}

type dalfoxResult struct {
	Type       string `json:"type"`
	InjectType string `json:"inject_type"`
	Method     string `json:"method"`
	Data       string `json:"data"`
	Param      string `json:"param"`
	Severity   string `json:"severity"`
	CWE        string `json:"cwe"`
	MessageStr string `json:"message_str"`
}

// runDalfox runs Dalfox XSS detection against URLs that carry query parameters.
// Opt-in and active: it sends XSS probe payloads, so it is gated behind -xss,
// scope/safety filtered, rate limited, carries the research header, and uses
// Dalfox's default (detection-only) payloads — no custom/weaponized payloads.
func runDalfox(ctx context.Context, candidates []string, p Profile, rules []string, warnings *[]string) []Finding {
	if _, err := exec.LookPath("dalfox"); err != nil {
		*warnings = append(*warnings, "dalfox yok; XSS tespiti atlandı (go install github.com/hahwul/dalfox/v2@latest)")
		return nil
	}
	targets := []string{}
	for _, u := range safety.FilterSafeScopedURLs(candidates, rules) {
		if strings.Contains(u, "?") && strings.Contains(u, "=") {
			targets = append(targets, u)
		}
	}
	targets = uniq(targets)
	if len(targets) == 0 {
		*warnings = append(*warnings, "dalfox: parametreli URL bulunamadı; XSS tespiti atlandı")
		return nil
	}
	inputFile, cleanInput, err := writeTempList(targets)
	if err != nil {
		*warnings = append(*warnings, "dalfox giriş dosyası oluşturulamadı: "+err.Error())
		return nil
	}
	defer cleanInput()
	outFile, err := os.CreateTemp("", "reconixia-dalfox-*.json")
	if err != nil {
		*warnings = append(*warnings, "dalfox çıktı dosyası oluşturulamadı: "+err.Error())
		return nil
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	delayMs := 0
	if p.Rate > 0 {
		delayMs = 1000 / p.Rate
	}
	args := []string{
		"file", inputFile,
		"--format", "json",
		"-o", outPath,
		"--skip-bav", // yalnızca XSS'e odaklan, ek zafiyet taramasını kapat
		"--silence",
		"--no-spinner",
		"--worker", fmt.Sprint(p.Threads),
		"--delay", fmt.Sprint(delayMs),
		"--timeout", fmt.Sprint(int(p.Timeout.Seconds())),
	}
	if h := researchHeaderArg(); h != "" {
		args = append(args, "-H", h)
	}
	runCtx, cancel := context.WithTimeout(ctx, p.GAUTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "dalfox", args...)
	_, _ = cmd.CombinedOutput()
	if runCtx.Err() == context.DeadlineExceeded {
		*warnings = append(*warnings, fmt.Sprintf("dalfox timeout (%s); kısmi sonuç kullanıldı", p.GAUTimeout))
	}
	raw, err := os.ReadFile(outPath)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var results []dalfoxResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil
	}
	findings := []Finding{}
	for _, r := range results {
		u := strings.TrimSpace(r.Data)
		if u == "" || !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
			continue
		}
		conf, ftype := "medium", "xss_reflected_candidate"
		if strings.EqualFold(r.Type, "V") {
			conf, ftype = "high", "xss_verified_candidate"
		}
		note := "dalfox XSS (" + r.InjectType + ") param=" + r.Param
		if r.MessageStr != "" {
			note += "; " + r.MessageStr
		}
		note += "; verify manually with an authorized browser session"
		findings = append(findings, Finding{Type: ftype, URL: u, Status: 0, Confidence: conf, Note: note})
	}
	return findings
}

// arjunHostCap bounds how many live hosts arjun probes, since it is request-heavy.
func arjunHostCap(profileName string) int {
	switch profileName {
	case "fast":
		return 50
	case "stealth":
		return 10
	default:
		return 25
	}
}

type arjunEntry struct {
	Params []string `json:"params"`
}

// runArjun runs arjun against the live hosts to surface hidden parameters. It
// returns a flat "url?param" style list for the report plus structured
// Findings. Opt-in: arjun actively probes the target.
func runArjun(ctx context.Context, hosts []string, p Profile, rules []string, maxHosts int, warnings *[]string) ([]string, []Finding) {
	if _, err := exec.LookPath("arjun"); err != nil {
		*warnings = append(*warnings, "arjun yok; gizli parametre keşfi atlandı (pip install arjun)")
		return nil, nil
	}
	scoped := safety.FilterSafeScopedURLs(hosts, rules)
	if maxHosts > 0 && len(scoped) > maxHosts {
		scoped = scoped[:maxHosts]
		*warnings = append(*warnings, fmt.Sprintf("arjun hedefi %d host ile sınırlandı", maxHosts))
	}
	if len(scoped) == 0 {
		return nil, nil
	}
	inputFile, cleanInput, err := writeTempList(scoped)
	if err != nil {
		*warnings = append(*warnings, "arjun giriş dosyası oluşturulamadı: "+err.Error())
		return nil, nil
	}
	defer cleanInput()
	outFile, err := os.CreateTemp("", "reconixia-arjun-*.json")
	if err != nil {
		*warnings = append(*warnings, "arjun çıktı dosyası oluşturulamadı: "+err.Error())
		return nil, nil
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	args := []string{"-i", inputFile, "-oJ", outPath, "-t", fmt.Sprint(p.Threads), "--stable"}
	if h := researchHeaderArg(); h != "" {
		args = append(args, "--headers", h)
	}
	runCtx, cancel := context.WithTimeout(ctx, p.GAUTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "arjun", args...)
	if _, err := cmd.CombinedOutput(); err != nil && runCtx.Err() == nil {
		*warnings = append(*warnings, "arjun çalıştırılamadı: "+err.Error())
		// arjun still may have written partial output; fall through to parse.
	}
	if runCtx.Err() == context.DeadlineExceeded {
		*warnings = append(*warnings, fmt.Sprintf("arjun timeout (%s)", p.GAUTimeout))
	}

	raw, err := os.ReadFile(outPath)
	if err != nil || len(raw) == 0 {
		return nil, nil
	}
	parsed := map[string]arjunEntry{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		// Older arjun writes a list of {url, params}. Try that shape.
		var list []struct {
			URL    string   `json:"url"`
			Params []string `json:"params"`
		}
		if json.Unmarshal(raw, &list) == nil {
			parsed = map[string]arjunEntry{}
			for _, it := range list {
				parsed[it.URL] = arjunEntry{Params: it.Params}
			}
		}
	}
	flat := []string{}
	findings := []Finding{}
	for u, e := range parsed {
		if len(e.Params) == 0 {
			continue
		}
		if !safety.IsSafeFetchURL(u) || !safety.ScopeAllowsURL(u, rules) {
			continue
		}
		flat = append(flat, u+" -> "+strings.Join(e.Params, ","))
		findings = append(findings, Finding{
			Type:       "discovered_parameter",
			URL:        u,
			Status:     0,
			Confidence: "medium",
			Note:       "arjun hidden parameters: " + strings.Join(e.Params, ", ") + "; review for IDOR/injection with authorized accounts only",
		})
	}
	return uniq(flat), findings
}

// pruneDeadURLs drops passive URLs that are clearly dead (404/410/5xx/unreachable)
// while keeping anything that returns a meaningful status. Uses httpx when
// available for speed, otherwise a safe-client HEAD fallback.
func pruneDeadURLs(ctx context.Context, urls []string, p Profile, rules []string, client *http.Client, warnings *[]string) []string {
	scoped := safety.FilterSafeScopedURLs(urls, rules)
	if len(scoped) == 0 {
		return urls
	}
	if _, err := exec.LookPath("httpx"); err == nil {
		inputFile, clean, err := writeTempList(scoped)
		if err == nil {
			defer clean()
			runCtx, cancel := context.WithTimeout(ctx, p.GAUTimeout)
			defer cancel()
			cmd := exec.CommandContext(runCtx, "httpx",
				"-l", inputFile,
				"-silent",
				"-mc", "200,201,202,203,204,206,207,301,302,303,307,308,401,403,405,429",
				"-rate-limit", fmt.Sprint(p.Rate),
				"-threads", fmt.Sprint(p.Threads),
			)
			out, err := cmd.Output()
			if err == nil || runCtx.Err() == context.DeadlineExceeded {
				kept := safety.FilterSafeScopedURLs(firstURL(strings.Split(string(out), "\n")), rules)
				if len(kept) > 0 {
					*warnings = append(*warnings, fmt.Sprintf("ölü URL budama: %d → %d canlı URL", len(scoped), len(kept)))
					return kept
				}
			}
		}
	}
	// Fallback: concurrent HEAD with the SSRF-safe client.
	sem := make(chan struct{}, p.Threads)
	lim := newLimiter(p.Rate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	kept := []string{}
	for _, u := range scoped {
		u := u
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
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
			if err != nil {
				return
			}
			researchheaders.Apply(req)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == 404 || resp.StatusCode == 410 || resp.StatusCode >= 500 {
				return
			}
			mu.Lock()
			kept = append(kept, u)
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(kept) == 0 {
		return urls
	}
	*warnings = append(*warnings, fmt.Sprintf("ölü URL budama (fallback): %d → %d canlı URL", len(scoped), len(kept)))
	return uniq(kept)
}
