package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Veyselyigit21/Reconixia/internal/checkpoint"
	"github.com/Veyselyigit21/Reconixia/internal/redact"
	"github.com/Veyselyigit21/Reconixia/internal/takeover"
)

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

func markCheckpoint(path string, st *checkpoint.State, step string, warnings *[]string) {
	next, err := checkpoint.MarkDone(path, *st, step)
	if err != nil {
		*warnings = append(*warnings, "checkpoint yazilamadi: "+err.Error())
		return
	}
	*st = next
}

func resumeLines(enabled bool, st checkpoint.State, step, path string, warnings *[]string) ([]string, bool) {
	if !enabled || !checkpoint.IsDone(st, step) {
		return nil, false
	}
	lines, err := readLines(path)
	if err != nil {
		*warnings = append(*warnings, "resume "+step+" okunamadi: "+err.Error())
		return nil, false
	}
	fmt.Println("[resume]", step)
	return lines, true
}

func resumeFindings(enabled bool, st checkpoint.State, step, path string, warnings *[]string) ([]Finding, bool) {
	if !enabled || !checkpoint.IsDone(st, step) {
		return nil, false
	}
	findings, err := readFindings(path)
	if err != nil {
		*warnings = append(*warnings, "resume "+step+" okunamadi: "+err.Error())
		return nil, false
	}
	fmt.Println("[resume]", step)
	return findings, true
}

func resumeEndpointProbes(enabled bool, st checkpoint.State, step, path string, warnings *[]string) ([]EndpointProbe, bool) {
	if !enabled || !checkpoint.IsDone(st, step) {
		return nil, false
	}
	probes, err := readEndpointProbes(path)
	if err != nil {
		*warnings = append(*warnings, "resume "+step+" okunamadi: "+err.Error())
		return nil, false
	}
	fmt.Println("[resume]", step)
	return probes, true
}

func readFindings(path string) ([]Finding, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(line, " | ", 5)
		if len(parts) < 5 {
			continue
		}
		status, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
		out = append(out, Finding{
			URL:        strings.TrimSpace(parts[0]),
			Status:     status,
			Type:       strings.TrimSpace(parts[2]),
			Confidence: strings.TrimSpace(parts[3]),
			Note:       strings.TrimSpace(parts[4]),
		})
	}
	return out, nil
}

func readEndpointProbes(path string) ([]EndpointProbe, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]EndpointProbe, 0, len(lines))
	for _, line := range lines {
		var probe EndpointProbe
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			continue
		}
		out = append(out, probe)
	}
	return out, nil
}

func takeoverToFindings(in []takeover.Finding) []Finding {
	out := make([]Finding, 0, len(in))
	for _, tf := range in {
		out = append(out, Finding{
			Type:       tf.Type,
			URL:        tf.URL,
			Status:     tf.Status,
			Confidence: tf.Confidence,
			Note:       tf.Note,
		})
	}
	return out
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeLines(path string, lines []string) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("[WARN] dizin olusturulamadi %s: %v", filepath.Dir(path), err)
		return
	}
	if err := os.WriteFile(path, []byte(strings.Join(uniq(lines), "\n")+"\n"), 0600); err != nil {
		log.Printf("[WARN] dosya yazilamadi %s: %v", path, err)
	}
}

func writeFindings(path string, fs []Finding) {
	var b strings.Builder
	for _, f := range fs {
		f.URL = redact.String(f.URL)
		f.Note = redact.String(f.Note)
		b.WriteString(fmt.Sprintf("%s | %d | %s | %s | %s\n", f.URL, f.Status, f.Type, f.Confidence, f.Note))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] findings yazilamadi: %v", err)
	}
}

func writeEndpointProbes(path string, probes []EndpointProbe) {
	var b strings.Builder
	for _, p := range probes {
		p.Endpoint = redact.String(p.Endpoint)
		p.URL = redact.String(p.URL)
		p.ContentType = redact.String(p.ContentType)
		p.Allow = redact.String(p.Allow)
		p.CORSAllowOrigin = redact.String(p.CORSAllowOrigin)
		p.Note = redact.String(p.Note)
		for i := range p.SensitiveFields {
			p.SensitiveFields[i].Path = redact.String(p.SensitiveFields[i].Path)
			p.SensitiveFields[i].Category = redact.String(p.SensitiveFields[i].Category)
			p.SensitiveFields[i].Severity = redact.String(p.SensitiveFields[i].Severity)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			continue
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] endpoint probes yazilamadi: %v", err)
	}
}

func writeReport(ws string, r Report) {
	r = redactReport(r)
	raw, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(ws, "report.json"), raw, 0600); err != nil {
		log.Printf("[WARN] report.json yazilamadi: %v", err)
	}
	var b strings.Builder
	b.WriteString("# Reconixia Raporu\n\n")
	b.WriteString("Hedef: `" + r.Target + "`\n\n")
	b.WriteString(fmt.Sprintf("Profil: `%s` | Rate: `%d/sn` | Threads: `%d`\n\n", r.Profile.Name, r.Profile.Rate, r.Profile.Threads))
	b.WriteString(fmt.Sprintf("Alt alan adi: **%d**  \nCanli hedef: **%d**  \nPasif URL: **%d**  \nJS: **%d**  \nEndpoint: **%d**  \nEndpoint probe: **%d**  \nBulgu: **%d**\n\n",
		len(r.Subdomains), len(r.LiveHosts), len(r.PassiveURLs), len(r.JSFiles), len(r.Endpoints), len(r.EndpointProbes), len(r.Findings)))
	if len(r.Warnings) > 0 {
		b.WriteString("## Uyarilar\n\n")
		for _, w := range r.Warnings {
			b.WriteString("- " + w + "\n")
		}
	}
	if len(r.EndpointProbes) > 0 {
		b.WriteString("\n## Endpoint Probes\n\n")
		for _, p := range r.EndpointProbes {
			risk := ""
			if p.RiskScore > 0 {
				risk = fmt.Sprintf(" risk:%s/%d fields:%s", p.Risk, p.RiskScore, summarizeSensitiveFields(p.SensitiveFields))
			}
			b.WriteString(fmt.Sprintf("- `%s` GET:%d HEAD:%d OPTIONS:%d `%s`%s %d bytes - %s\n",
				p.URL, p.GETStatus, p.HEADStatus, p.OPTIONSStatus, p.Classification, risk, p.Size, p.Note))
		}
	}
	if len(r.TechSummary) > 0 {
		b.WriteString("\n## Tech Priority\n\n")
		for _, t := range r.TechSummary {
			b.WriteString(fmt.Sprintf("- `%s` risk:%s hosts:%d\n", t.Name, t.Risk, t.Hosts))
		}
	}
	if len(r.DiscoveredParams) > 0 {
		b.WriteString("\n## Discovered Parameters\n\n")
		for _, p := range r.DiscoveredParams {
			b.WriteString("- `" + p + "`\n")
		}
	}
	b.WriteString("\n## Oncelikli Bulgular\n\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("- `%s` [%d] %s / %s - %s\n", f.URL, f.Status, f.Type, f.Confidence, f.Note))
	}
	if err := os.WriteFile(filepath.Join(ws, "report.md"), []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] report.md yazilamadi: %v", err)
	}
}

func redactReport(r Report) Report {
	r.Subdomains = redact.Strings(r.Subdomains)
	r.LiveHosts = redact.Strings(r.LiveHosts)
	r.PassiveURLs = redact.Strings(r.PassiveURLs)
	r.JSFiles = redact.Strings(r.JSFiles)
	r.Endpoints = redact.Strings(r.Endpoints)
	r.Warnings = redact.Strings(r.Warnings)
	r.ExportTarget = redact.String(r.ExportTarget)
	for i := range r.EndpointProbes {
		r.EndpointProbes[i].Endpoint = redact.String(r.EndpointProbes[i].Endpoint)
		r.EndpointProbes[i].URL = redact.String(r.EndpointProbes[i].URL)
		r.EndpointProbes[i].ContentType = redact.String(r.EndpointProbes[i].ContentType)
		r.EndpointProbes[i].Allow = redact.String(r.EndpointProbes[i].Allow)
		r.EndpointProbes[i].CORSAllowOrigin = redact.String(r.EndpointProbes[i].CORSAllowOrigin)
		r.EndpointProbes[i].Note = redact.String(r.EndpointProbes[i].Note)
		for j := range r.EndpointProbes[i].SensitiveFields {
			r.EndpointProbes[i].SensitiveFields[j].Path = redact.String(r.EndpointProbes[i].SensitiveFields[j].Path)
			r.EndpointProbes[i].SensitiveFields[j].Category = redact.String(r.EndpointProbes[i].SensitiveFields[j].Category)
			r.EndpointProbes[i].SensitiveFields[j].Severity = redact.String(r.EndpointProbes[i].SensitiveFields[j].Severity)
		}
	}
	for i := range r.Findings {
		r.Findings[i].URL = redact.String(r.Findings[i].URL)
		r.Findings[i].Note = redact.String(r.Findings[i].Note)
	}
	r.DiscoveredParams = redact.Strings(r.DiscoveredParams)
	for i := range r.TechSummary {
		r.TechSummary[i].Examples = redact.Strings(r.TechSummary[i].Examples)
	}
	return r
}
