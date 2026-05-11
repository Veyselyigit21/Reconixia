package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

type Report struct {
	Target      string    `json:"target"`
	Subdomains  []string  `json:"subdomains"`
	LiveHosts   []string  `json:"live_hosts"`
	PassiveURLs []string  `json:"passive_urls"`
	JSFiles     []string  `json:"js_files"`
	Endpoints   []string  `json:"endpoints"`
	Findings    []Finding `json:"findings"`
}

type Finding struct {
	Type string `json:"type"`
	URL  string `json:"url"`
	Note string `json:"note"`
}

func main() {
	oldPath := flag.String("old", "", "eski report.json")
	newPath := flag.String("new", "", "yeni report.json")
	flag.Parse()
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "kullanım: reconixia-diff -old old/report.json -new new/report.json")
		os.Exit(1)
	}
	oldReport, err := load(*oldPath)
	if err != nil { fail(err) }
	newReport, err := load(*newPath)
	if err != nil { fail(err) }

	fmt.Println("# Reconixia Report Diff")
	fmt.Println()
	fmt.Println("Old target:", oldReport.Target)
	fmt.Println("New target:", newReport.Target)
	fmt.Println()
	printDiff("Yeni subdomain", oldReport.Subdomains, newReport.Subdomains)
	printDiff("Yeni canlı hedef", oldReport.LiveHosts, newReport.LiveHosts)
	printDiff("Yeni pasif URL", oldReport.PassiveURLs, newReport.PassiveURLs)
	printDiff("Yeni JS dosyası", oldReport.JSFiles, newReport.JSFiles)
	printDiff("Yeni endpoint", oldReport.Endpoints, newReport.Endpoints)
	printDiff("Yeni bulgu", findingsToKeys(oldReport.Findings), findingsToKeys(newReport.Findings))
}

func load(path string) (Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil { return Report{}, err }
	var r Report
	return r, json.Unmarshal(raw, &r)
}

func printDiff(title string, oldItems, newItems []string) {
	added := added(oldItems, newItems)
	fmt.Printf("## %s (%d)\n", title, len(added))
	if len(added) == 0 {
		fmt.Println("- Yok")
		fmt.Println()
		return
	}
	limit := len(added)
	if limit > 100 { limit = 100 }
	for i := 0; i < limit; i++ { fmt.Println("-", added[i]) }
	if len(added) > limit { fmt.Printf("- ... %d kayıt daha var\n", len(added)-limit) }
	fmt.Println()
}

func added(oldItems, newItems []string) []string {
	oldSet := map[string]bool{}
	for _, item := range oldItems { oldSet[item] = true }
	var out []string
	seen := map[string]bool{}
	for _, item := range newItems {
		if item == "" || oldSet[item] || seen[item] { continue }
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func findingsToKeys(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Type+" | "+f.URL+" | "+f.Note)
	}
	return out
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "hata:", err)
	os.Exit(1)
}
