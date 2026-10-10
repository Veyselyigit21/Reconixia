package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/checkpoint"
	"github.com/Veyselyigit21/Reconixia/internal/cloudbuckets"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
	"github.com/Veyselyigit21/Reconixia/internal/subenum"
	"github.com/Veyselyigit21/Reconixia/internal/takeover"
	"github.com/Veyselyigit21/Reconixia/internal/techrank"
	"github.com/Veyselyigit21/Reconixia/internal/workspace"
)

func runResumable(ctx context.Context, o Options, target string, p Profile) (*Report, error) {
	ws := filepath.Join("results", target)
	lock, err := workspace.AcquireLock(ws, target, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := lock.Release(); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] workspace lock kaldirilamadi: %v", err)
		}
	}()

	for _, d := range []string{"raw", "processed", "export", "logs"} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0700); err != nil {
			log.Printf("[WARN] dizin olusturulamadi: %v", err)
		}
	}

	warnings := []string{}
	checkpointPath := filepath.Join(ws, "checkpoint_run.json")
	if o.ResetResume {
		if err := os.Remove(checkpointPath); err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, "checkpoint silinemedi: "+err.Error())
		}
	}
	ckpt, err := checkpoint.Load(checkpointPath, target)
	if err != nil {
		return nil, err
	}
	defer func() {
		if ctx.Err() != nil {
			_ = checkpoint.MarkInterrupted(checkpointPath, ckpt, ctx.Err().Error())
		}
	}()

	scopeRules := loadScope(o.ScopeFile, target, &warnings)
	client := safety.SafeHTTPClient(p.Timeout)
	seedURL := ""
	if strings.TrimSpace(o.SeedURL) != "" {
		seedURL, err = normalizeSeedURL(o.SeedURL, scopeRules)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, "seed-url kullanildi; subfinder/httpx yerine verilen base URL tarandi")
	}

	subdomainsPath := filepath.Join(ws, "raw", "subdomains.txt")
	livePath := filepath.Join(ws, "processed", "live_hosts.txt")
	httpxDetailedPath := filepath.Join(ws, "processed", "httpx_detailed.jsonl")
	targetsPath := filepath.Join(ws, "export", "targets.txt")
	passivePath := filepath.Join(ws, "processed", "passive_urls.txt")
	discoveredParamsPath := filepath.Join(ws, "processed", "discovered_params.txt")
	bucketFindingsPath := filepath.Join(ws, "processed", "findings_buckets.txt")
	paramFindingsPath := filepath.Join(ws, "processed", "findings_params.txt")
	xssFindingsPath := filepath.Join(ws, "processed", "findings_xss.txt")
	jsPath := filepath.Join(ws, "processed", "js_files.txt")
	endpointsPath := filepath.Join(ws, "processed", "endpoints.txt")
	endpointProbesPath := filepath.Join(ws, "processed", "endpoint_probes.jsonl")
	discoverFindingsPath := filepath.Join(ws, "processed", "findings_discover.txt")
	headerFindingsPath := filepath.Join(ws, "processed", "findings_headers.txt")
	takeoverFindingsPath := filepath.Join(ws, "processed", "findings_takeover.txt")
	interestingPath := filepath.Join(ws, "processed", "interesting_paths.txt")
	nucleiPath := filepath.Join(ws, "processed", "nuclei_safe.txt")

	log.Println("[1/10] Alt alan adi kesfi")
	var subs []string
	if lines, ok := resumeLines(true, ckpt, "subfinder", subdomainsPath, &warnings); ok {
		subs = lines
	} else if seedURL != "" {
		subs = []string{target}
		writeLines(subdomainsPath, subs)
		markCheckpoint(checkpointPath, &ckpt, "subfinder", &warnings)
	} else {
		subs, err = subfinder(target, subdomainsPath)
		if err != nil {
			warnings = append(warnings, err.Error())
		}
		if !o.NoSubenum {
			sr := subenum.Passive(ctx, target, scopeRules, 25*time.Second)
			subs = append(subs, sr.Hosts...)
			warnings = append(warnings, sr.Warnings...)
			if len(sr.Sources) > 0 {
				parts := []string{}
				for k, v := range sr.Sources {
					parts = append(parts, fmt.Sprintf("%s=%d", k, v))
				}
				sort.Strings(parts)
				log.Println("    [+] pasif subdomain kaynakları:", strings.Join(parts, " "))
			}
		}
		if len(subs) == 0 {
			subs = []string{target}
		}
		subs = filterHostsByScope(subs, scopeRules)
		writeLines(subdomainsPath, subs)
		markCheckpoint(checkpointPath, &ckpt, "subfinder", &warnings)
	}

	log.Println("[2/10] Canli hedef kontrolu")
	var live []string
	if lines, ok := resumeLines(true, ckpt, "httpx", livePath, &warnings); ok {
		live = lines
	} else if seedURL != "" {
		live = []string{seedURL}
		writeLines(livePath, live)
		markCheckpoint(checkpointPath, &ckpt, "httpx", &warnings)
	} else {
		live, err = httpxLive(subdomainsPath, httpxDetailedPath, p)
		if err != nil {
			warnings = append(warnings, err.Error())
		}
		if len(live) == 0 {
			live = fallbackLive(ctx, subs, p, scopeRules, client)
		}
		live = safety.FilterSafeScopedURLs(live, scopeRules)
		writeLines(livePath, live)
		markCheckpoint(checkpointPath, &ckpt, "httpx", &warnings)
	}
	writeLines(targetsPath, live)

	log.Println("[3/10] Pasif URL toplama")
	var passive []string
	if lines, ok := resumeLines(true, ckpt, "passive", passivePath, &warnings); ok {
		passive = lines
	} else {
		noGAU := o.NoGAU || seedURL != ""
		if seedURL != "" && !o.NoGAU {
			warnings = append(warnings, "seed-url nedeniyle gau/wayback pasif toplama atlandi")
		}
		passive = passiveURLs(ctx, target, live, p, scopeRules, noGAU, &warnings, client)
		writeLines(passivePath, passive)
		markCheckpoint(checkpointPath, &ckpt, "passive", &warnings)
	}

	if o.PruneDead && !checkpoint.IsDone(ckpt, "prune_dead") {
		log.Println("[+] Ölü URL budama (httpx doğrulama)")
		passive = pruneDeadURLs(ctx, passive, p, scopeRules, client, &warnings)
		writeLines(passivePath, passive)
		markCheckpoint(checkpointPath, &ckpt, "prune_dead", &warnings)
	}

	if o.Katana && !checkpoint.IsDone(ckpt, "katana") {
		log.Println("[+] Katana derin crawl")
		if kurls := runKatana(ctx, targetsPath, p, scopeRules, &warnings); len(kurls) > 0 {
			passive = uniq(append(passive, kurls...))
			writeLines(passivePath, passive)
		}
		markCheckpoint(checkpointPath, &ckpt, "katana", &warnings)
	}

	log.Println("[4/10] JS ve endpoint cikarimi")
	var js, endpoints []string
	if cachedJS, ok := resumeLines(true, ckpt, "js", jsPath, &warnings); ok {
		if cachedEndpoints, ok := resumeLines(true, ckpt, "js", endpointsPath, &warnings); ok {
			js = cachedJS
			endpoints = cachedEndpoints
		}
	}
	if js == nil || endpoints == nil {
		js, endpoints = jsAndEndpoints(ctx, live, passive, p, scopeRules, client)
		writeLines(jsPath, js)
		writeLines(endpointsPath, endpoints)
		markCheckpoint(checkpointPath, &ckpt, "js", &warnings)
	}

	log.Println("[5/10] Endpoint probe")
	var endpointProbes []EndpointProbe
	if cached, ok := resumeEndpointProbes(true, ckpt, "endpoint_probe", endpointProbesPath, &warnings); ok {
		endpointProbes = cached
	} else {
		endpointProbes = probeEndpoints(ctx, live, endpoints, p, scopeRules, client)
		writeEndpointProbes(endpointProbesPath, endpointProbes)
		markCheckpoint(checkpointPath, &ckpt, "endpoint_probe", &warnings)
	}

	log.Println("[6/10] Ilginc path kesfi")
	findings := []Finding{}
	if cached, ok := resumeFindings(true, ckpt, "discover", discoverFindingsPath, &warnings); ok {
		findings = append(findings, cached...)
	} else {
		discoverFindings := discover(ctx, live, loadWordlist(o.Wordlist), p, scopeRules, client)
		discoverFindings = append(discoverFindings, classifyEndpoints(endpoints)...)
		discoverFindings = append(discoverFindings, endpointProbeFindings(endpointProbes)...)
		discoverFindings = append(discoverFindings, secretScan(ctx, js, p, scopeRules, client)...)
		writeFindings(discoverFindingsPath, discoverFindings)
		findings = append(findings, discoverFindings...)
		markCheckpoint(checkpointPath, &ckpt, "discover", &warnings)
	}

	log.Println("[7/10] CORS ve Security Header analizi")
	if cached, ok := resumeFindings(true, ckpt, "headers", headerFindingsPath, &warnings); ok {
		findings = append(findings, cached...)
	} else {
		headerFindings := []Finding{}
		if o.NoHeaders {
			warnings = append(warnings, "header analizi kullanici tercihiyle atlandi")
		} else {
			headerFindings = analyzeHeaders(live, p, scopeRules, client)
		}
		writeFindings(headerFindingsPath, headerFindings)
		findings = append(findings, headerFindings...)
		markCheckpoint(checkpointPath, &ckpt, "headers", &warnings)
	}
	writeFindings(interestingPath, findings)

	log.Println("[8/10] Nuclei safe scan")
	if checkpoint.IsDone(ckpt, "nuclei") && fileExists(nucleiPath) {
		log.Println("[resume] nuclei")
	} else {
		if o.NoNuclei {
			warnings = append(warnings, "nuclei kullanici tercihiyle atlandi")
		} else {
			if o.DAST {
				log.Println("    [+] nuclei DAST fuzzing etkin")
			}
			if err := nuclei(targetsPath, nucleiPath, p, o.Severity, o.DAST); err != nil {
				warnings = append(warnings, err.Error())
			}
		}
		markCheckpoint(checkpointPath, &ckpt, "nuclei", &warnings)
	}

	log.Println("[9/10] Subdomain takeover on analizi")
	if cached, ok := resumeFindings(true, ckpt, "takeover", takeoverFindingsPath, &warnings); ok {
		findings = append(findings, cached...)
	} else {
		takeoverFindings := takeoverToFindings(takeover.AnalyzeSubdomains(subs, scopeRules))
		writeFindings(takeoverFindingsPath, takeoverFindings)
		findings = append(findings, takeoverFindings...)
		markCheckpoint(checkpointPath, &ckpt, "takeover", &warnings)
	}

	log.Println("[+] Cloud bucket exposure analizi")
	if cached, ok := resumeFindings(true, ckpt, "buckets", bucketFindingsPath, &warnings); ok {
		findings = append(findings, cached...)
	} else {
		bucketFindings := []Finding{}
		if o.NoBuckets {
			warnings = append(warnings, "cloud bucket analizi kullanıcı tercihiyle atlandı")
		} else {
			for _, bf := range cloudbuckets.Scan(ctx, p.Timeout, 0, live, passive, endpoints, js) {
				bucketFindings = append(bucketFindings, Finding{
					Type:       bf.Type,
					URL:        bf.URL,
					Status:     bf.Status,
					Confidence: bf.Confidence,
					Note:       bf.Note,
				})
			}
		}
		writeFindings(bucketFindingsPath, bucketFindings)
		findings = append(findings, bucketFindings...)
		markCheckpoint(checkpointPath, &ckpt, "buckets", &warnings)
	}

	if o.XSS {
		if cached, ok := resumeFindings(true, ckpt, "xss", xssFindingsPath, &warnings); ok {
			findings = append(findings, cached...)
		} else {
			log.Println("[+] Dalfox XSS tespiti")
			xssFindings := runDalfox(ctx, passive, p, scopeRules, &warnings)
			writeFindings(xssFindingsPath, xssFindings)
			findings = append(findings, xssFindings...)
			markCheckpoint(checkpointPath, &ckpt, "xss", &warnings)
		}
	}

	var discoveredParams []string
	if o.Arjun {
		if checkpoint.IsDone(ckpt, "arjun") {
			discoveredParams, _ = readLines(discoveredParamsPath)
			if pf, perr := readFindings(paramFindingsPath); perr == nil {
				findings = append(findings, pf...)
			}
		} else {
			log.Println("[+] Arjun gizli parametre keşfi")
			flat, paramFindings := runArjun(ctx, live, p, scopeRules, arjunHostCap(p.Name), &warnings)
			discoveredParams = flat
			writeLines(discoveredParamsPath, flat)
			writeFindings(paramFindingsPath, paramFindings)
			findings = append(findings, paramFindings...)
			markCheckpoint(checkpointPath, &ckpt, "arjun", &warnings)
		}
	}

	var techSummary []techrank.Item
	if detailedLines, derr := readLines(httpxDetailedPath); derr == nil && len(detailedLines) > 0 {
		techSummary = techrank.Rank(detailedLines)
	}

	log.Println("[10/10] Rapor")
	report := &Report{
		Target:           target,
		Profile:          p,
		GeneratedAt:      time.Now().Format(time.RFC3339),
		Subdomains:       subs,
		LiveHosts:        live,
		PassiveURLs:      passive,
		JSFiles:          js,
		Endpoints:        endpoints,
		EndpointProbes:   endpointProbes,
		Findings:         deduplicateFindings(findings),
		TechSummary:      techSummary,
		DiscoveredParams: discoveredParams,
		Warnings:         warnings,
		ExportTarget:     targetsPath,
	}
	writeReport(ws, *report)
	markCheckpoint(checkpointPath, &ckpt, "report", &warnings)
	log.Println("Tamamlandi:", ws)
	return report, nil
}

func normalizeSeedURL(raw string, rules []string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("gecersiz seed-url: %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("seed-url sadece http/https olabilir: %q", raw)
	}
	base := u.Scheme + "://" + u.Host
	if !safety.IsSafeFetchURL(base) || !safety.ScopeAllowsURL(base, rules) {
		return "", fmt.Errorf("seed-url guvenli degil veya scope disi: %q", raw)
	}
	return strings.TrimRight(base, "/"), nil
}
