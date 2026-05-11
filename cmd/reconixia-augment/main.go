package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/cookies"
	"github.com/Veyselyigit21/Reconixia/internal/htmlreport"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
	"github.com/Veyselyigit21/Reconixia/internal/takeover"
)

type Report struct {
	Target       string    `json:"target"`
	GeneratedAt  string    `json:"generated_at"`
	ExportTarget string    `json:"export_target"`
	Subdomains   []string  `json:"subdomains"`
	LiveHosts    []string  `json:"live_hosts"`
	PassiveURLs  []string  `json:"passive_urls"`
	JSFiles      []string  `json:"js_files"`
	Endpoints    []string  `json:"endpoints"`
	Warnings     []string  `json:"warnings"`
	Findings     []Finding `json:"findings"`
	Profile      Profile   `json:"profile"`
}

type Profile struct {
	Name    string `json:"name"`
	Rate    int    `json:"rate_per_second"`
	Threads int    `json:"threads"`
}

type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

func main() {
	target := flag.String("target", "", "hedef domain")
	input := flag.String("input", "", "report.json yolu")
	output := flag.String("output", "", "güncellenecek report.json yolu; boşsa input üzerine yazar")
	noTakeover := flag.Bool("no-takeover", false, "subdomain takeover ön analizini atla")
	noCookies := flag.Bool("no-cookies", false, "cookie security analizini atla")
	renderHTML := flag.Bool("html", true, "report.html dosyasını da güncelle")
	flag.Parse()

	in := strings.TrimSpace(*input)
	if in == "" {
		if *target == "" {
			fail("-target veya -input gerekli")
		}
		t, ok := safety.NormalizeTarget(*target)
		if !ok {
			fail("geçersiz hedef")
		}
		in = filepath.Join("results", t, "report.json")
	}
	out := strings.TrimSpace(*output)
	if out == "" {
		out = in
	}

	report, err := loadReport(in)
	if err != nil {
		fail(err.Error())
	}
	if report.Target == "" {
		fail("report.json içinde target yok")
	}
	if _, ok := safety.NormalizeTarget(report.Target); !ok {
		fail("report target güvenli değil")
	}

	rules := []string{report.Target, "*." + report.Target}
	var added []Finding

	if !*noTakeover {
		for _, f := range takeover.AnalyzeSubdomains(report.Subdomains, rules) {
			added = append(added, Finding{Type: f.Type, URL: f.URL, Status: f.Status, Confidence: f.Confidence, Note: f.Note})
		}
	}

	if !*noCookies {
		client := &http.Client{Timeout: 10 * time.Second}
		for _, u := range safety.FilterSafeScopedURLs(report.LiveHosts, rules) {
			for _, f := range cookies.AnalyzeURL(client, u, rules) {
				added = append(added, Finding{Type: f.Type, URL: f.URL, Status: f.Status, Confidence: f.Confidence, Note: f.Note})
			}
		}
	}

	report.Findings = mergeFindings(report.Findings, added)
	report.Warnings = appendUnique(report.Warnings, fmt.Sprintf("augment çalıştı: %d yeni takeover/cookie bulgusu işlendi", len(added)))
	if err := saveReport(out, report); err != nil {
		fail(err.Error())
	}
	fmt.Println("Rapor güncellendi:", out)
	fmt.Println("Eklenen/işlenen bulgu:", len(added))

	if *renderHTML {
		htmlOut := filepath.Join(filepath.Dir(out), "report.html")
		if err := htmlreport.RenderFromJSON(out, htmlOut); err != nil {
			fmt.Fprintln(os.Stderr, "HTML rapor hatası:", err)
		} else {
			fmt.Println("HTML rapor güncellendi:", htmlOut)
		}
	}
}

func loadReport(path string) (Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	var r Report
	return r, json.Unmarshal(raw, &r)
}

func saveReport(path string, r Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0644)
}

func mergeFindings(existing, added []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(existing)+len(added))
	for _, f := range append(existing, added...) {
		key := f.Type + "\x00" + f.URL + "\x00" + f.Note
		if key == "\x00\x00" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].Type < out[j].Type
		}
		return score(out[i].Confidence) > score(out[j].Confidence)
	})
	return out
}

func score(conf string) int {
	switch strings.ToLower(conf) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "hata:", msg)
	os.Exit(1)
}
