package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
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
	Type       string `json:"type"`
	URL        string `json:"url"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

type diffSection struct {
	Title string
	Items []string
}

func main() {
	oldPath := flag.String("old", "", "old report.json")
	newPath := flag.String("new", "", "new report.json")
	htmlOut := flag.Bool("html", false, "render HTML diff")
	output := flag.String("output", "", "HTML output path, default stdout")
	flag.Parse()
	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "usage: reconixia-diff -old old/report.json -new new/report.json [-html -output diff.html]")
		os.Exit(1)
	}
	oldReport, err := load(*oldPath)
	if err != nil {
		fail(err)
	}
	newReport, err := load(*newPath)
	if err != nil {
		fail(err)
	}
	sections := buildDiff(oldReport, newReport)
	if *htmlOut {
		rendered := renderHTMLDiff(oldReport, newReport, sections)
		if *output != "" {
			if err := os.WriteFile(*output, []byte(rendered), 0644); err != nil {
				fail(err)
			}
			fmt.Println("HTML diff written:", *output)
			return
		}
		fmt.Print(rendered)
		return
	}
	renderMarkdown(oldReport, newReport, sections)
}

func buildDiff(oldReport, newReport Report) []diffSection {
	return []diffSection{
		{Title: "New subdomains", Items: added(oldReport.Subdomains, newReport.Subdomains)},
		{Title: "New live hosts", Items: added(oldReport.LiveHosts, newReport.LiveHosts)},
		{Title: "New passive URLs", Items: added(oldReport.PassiveURLs, newReport.PassiveURLs)},
		{Title: "New JS files", Items: added(oldReport.JSFiles, newReport.JSFiles)},
		{Title: "New endpoints", Items: added(oldReport.Endpoints, newReport.Endpoints)},
		{Title: "New findings", Items: added(findingsToKeys(oldReport.Findings), findingsToKeys(newReport.Findings))},
	}
}

func renderMarkdown(oldReport, newReport Report, sections []diffSection) {
	fmt.Println("# Reconixia Report Diff")
	fmt.Println()
	fmt.Println("Old target:", oldReport.Target)
	fmt.Println("New target:", newReport.Target)
	fmt.Println()
	for _, section := range sections {
		printSection(section)
	}
}

func printSection(section diffSection) {
	fmt.Printf("## %s (%d)\n", section.Title, len(section.Items))
	if len(section.Items) == 0 {
		fmt.Println("- None")
		fmt.Println()
		return
	}
	limit := len(section.Items)
	if limit > 100 {
		limit = 100
	}
	for i := 0; i < limit; i++ {
		fmt.Println("-", section.Items[i])
	}
	if len(section.Items) > limit {
		fmt.Printf("- ... %d more records\n", len(section.Items)-limit)
	}
	fmt.Println()
}

func renderHTMLDiff(oldReport, newReport Report, sections []diffSection) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString("<title>Reconixia Diff - " + esc(newReport.Target) + "</title>")
	b.WriteString(`<style>
body{margin:0;background:#0b1020;color:#e5e7eb;font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.45}main{max-width:1180px;margin:0 auto;padding:28px 18px 72px}header,section{border:1px solid #263244;background:#111827;border-radius:8px;padding:16px;margin-bottom:14px}h1{margin:0 0 6px;font-size:28px}h2{margin:0 0 10px;font-size:18px}.muted{color:#94a3b8}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:16px 0}.stat{border:1px solid #263244;background:#0f172a;border-radius:8px;padding:12px}.stat span{display:block;color:#94a3b8}.stat b{font-size:24px}.toolbar{display:grid;grid-template-columns:1fr 220px;gap:10px;margin-bottom:12px}input,select{width:100%;background:#0b1220;color:#e5e7eb;border:1px solid #263244;border-radius:6px;padding:8px;font:inherit}ul{margin:0;padding-left:20px}li{margin:6px 0}code{word-break:break-all;color:#d8b4fe}.empty{color:#94a3b8;font-style:italic}@media(max-width:920px){.grid,.toolbar{grid-template-columns:1fr}}
</style>`)
	b.WriteString(`</head><body><main><header><h1>Reconixia Diff</h1><p class="muted">Old target <b>`)
	b.WriteString(esc(oldReport.Target))
	b.WriteString(`</b> - New target <b>`)
	b.WriteString(esc(newReport.Target))
	b.WriteString(`</b></p></header><div class="grid">`)
	for _, section := range sections {
		b.WriteString(`<div class="stat"><span>`)
		b.WriteString(esc(section.Title))
		b.WriteString(`</span><b>`)
		b.WriteString(fmt.Sprint(len(section.Items)))
		b.WriteString(`</b></div>`)
	}
	b.WriteString(`</div><section><div class="toolbar"><input id="diffSearch" type="search" placeholder="Search new assets or findings"><select id="sectionFilter"><option value="">All sections</option>`)
	for _, section := range sections {
		b.WriteString(`<option value="` + esc(slug(section.Title)) + `">` + esc(section.Title) + `</option>`)
	}
	b.WriteString(`</select></div></section>`)
	for _, section := range sections {
		b.WriteString(`<section class="diff-section" data-section="` + esc(slug(section.Title)) + `"><h2>`)
		b.WriteString(esc(section.Title))
		b.WriteString(fmt.Sprintf(" (%d)", len(section.Items)))
		b.WriteString(`</h2>`)
		if len(section.Items) == 0 {
			b.WriteString(`<p class="empty">No new records.</p></section>`)
			continue
		}
		b.WriteString(`<ul>`)
		for _, item := range limitItems(section.Items, 500) {
			b.WriteString(`<li data-text="` + esc(strings.ToLower(item)) + `"><code>` + esc(item) + `</code></li>`)
		}
		if len(section.Items) > 500 {
			b.WriteString(fmt.Sprintf(`<li class="empty">... %d more records in JSON diff source.</li>`, len(section.Items)-500))
		}
		b.WriteString(`</ul></section>`)
	}
	b.WriteString(`<script>
const q=document.querySelector("#diffSearch");
const filter=document.querySelector("#sectionFilter");
const sections=[...document.querySelectorAll(".diff-section")];
function apply(){
  const query=(q.value||"").trim().toLowerCase();
  const sectionName=filter.value||"";
  sections.forEach(section=>{
    const sectionOk=!sectionName || section.dataset.section===sectionName;
    let visibleItems=0;
    section.querySelectorAll("li[data-text]").forEach(item=>{
      const show=!query || (item.dataset.text||"").includes(query);
      item.hidden=!show;
      if(show) visibleItems++;
    });
    section.hidden=!sectionOk || (query && visibleItems===0);
  });
}
[q,filter].forEach(el=>el.addEventListener("input",apply));
apply();
</script></main></body></html>`)
	return b.String()
}

func load(path string) (Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	var r Report
	return r, json.Unmarshal(raw, &r)
}

func added(oldItems, newItems []string) []string {
	oldSet := map[string]bool{}
	for _, item := range oldItems {
		oldSet[item] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range newItems {
		if item == "" || oldSet[item] || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func findingsToKeys(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Confidence+" | "+f.Type+" | "+f.URL+" | "+f.Note)
	}
	return out
}

func limitItems(items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func slug(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

func esc(s string) string { return html.EscapeString(s) }

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
