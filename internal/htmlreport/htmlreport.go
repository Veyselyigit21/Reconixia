package htmlreport

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
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

func RenderFromJSON(reportJSONPath, outputPath string) error {
	raw, err := os.ReadFile(reportJSONPath)
	if err != nil {
		return err
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	if outputPath == "" {
		outputPath = filepath.Join(filepath.Dir(reportJSONPath), "report.html")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(Render(report)), 0644)
}

func Render(r Report) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	b.WriteString("<title>Reconixia Raporu - "+esc(r.Target)+"</title>")
	b.WriteString(`<style>
:root{--bg:#0f172a;--card:#111827;--muted:#94a3b8;--text:#e5e7eb;--line:#263244;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--info:#38bdf8}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.45}
main{max-width:1180px;margin:0 auto;padding:32px 18px 80px}.hero{padding:24px;border:1px solid var(--line);border-radius:16px;background:linear-gradient(135deg,#111827,#0b1220)}
h1{margin:0 0 8px;font-size:32px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:18px 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}.stat b{font-size:24px;display:block}
section{margin-top:22px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}h2{margin:0 0 14px;font-size:20px}table{width:100%;border-collapse:collapse;overflow:hidden}td,th{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:#cbd5e1;font-weight:600}.tag{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;border:1px solid var(--line)}.high{color:var(--bad)}.medium{color:var(--warn)}.low{color:var(--info)}.info{color:var(--muted)}code{word-break:break-all;color:#c4b5fd}ul{margin:0;padding-left:20px}li{margin:6px 0}.empty{color:var(--muted);font-style:italic}@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}td,th{font-size:13px}}
</style>`)
	b.WriteString("</head><body><main>")
	b.WriteString("<div class=\"hero\"><h1>Reconixia Raporu</h1>")
	b.WriteString("<div class=\"muted\">Hedef: <b>"+esc(r.Target)+"</b> · Profil: <b>"+esc(r.Profile.Name)+"</b> · Tarih: "+esc(r.GeneratedAt)+"</div></div>")
	b.WriteString("<div class=\"grid\">")
	stat(&b, "Subdomain", len(r.Subdomains)); stat(&b, "Canlı Hedef", len(r.LiveHosts)); stat(&b, "Pasif URL", len(r.PassiveURLs)); stat(&b, "JS", len(r.JSFiles)); stat(&b, "Endpoint", len(r.Endpoints)); stat(&b, "Bulgu", len(r.Findings))
	b.WriteString("</div>")
	listSection(&b, "Uyarılar", r.Warnings)
	findingsSection(&b, r.Findings)
	listSection(&b, "Canlı Hedefler", r.LiveHosts)
	listSection(&b, "JS Dosyaları", r.JSFiles)
	listSection(&b, "Endpoint Adayları", r.Endpoints)
	b.WriteString("</main></body></html>")
	return b.String()
}

func stat(b *strings.Builder, title string, value int) {
	b.WriteString("<div class=\"stat\"><span class=\"muted\">"+esc(title)+"</span><b>")
	b.WriteString(fmt.Sprint(value))
	b.WriteString("</b></div>")
}

func findingsSection(b *strings.Builder, findings []Finding) {
	b.WriteString("<section><h2>Öncelikli Bulgular</h2>")
	if len(findings) == 0 { b.WriteString("<p class=\"empty\">Bulgu yok.</p></section>"); return }
	b.WriteString("<table><thead><tr><th>Tip</th><th>URL</th><th>Status</th><th>Güven</th><th>Not</th></tr></thead><tbody>")
	for _, f := range findings {
		conf := strings.ToLower(f.Confidence)
		if conf == "" { conf = "info" }
		b.WriteString("<tr><td><span class=\"tag\">"+esc(f.Type)+"</span></td><td><code>"+esc(f.URL)+"</code></td><td>")
		b.WriteString(fmt.Sprint(f.Status))
		b.WriteString("</td><td class=\""+esc(conf)+"\">"+esc(f.Confidence)+"</td><td>"+esc(f.Note)+"</td></tr>")
	}
	b.WriteString("</tbody></table></section>")
}

func listSection(b *strings.Builder, title string, values []string) {
	b.WriteString("<section><h2>"+esc(title)+"</h2>")
	if len(values) == 0 { b.WriteString("<p class=\"empty\">Kayıt yok.</p></section>"); return }
	b.WriteString("<ul>")
	limit := len(values)
	if limit > 250 { limit = 250 }
	for i := 0; i < limit; i++ { b.WriteString("<li><code>"+esc(values[i])+"</code></li>") }
	if len(values) > limit { b.WriteString("<li class=\"muted\">... "+fmt.Sprint(len(values)-limit)+" kayıt daha var. Tam liste için report.json dosyasına bak.</li>") }
	b.WriteString("</ul></section>")
}

func esc(s string) string { return html.EscapeString(s) }
