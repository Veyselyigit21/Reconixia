package htmlreport

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Report struct {
	Target         string          `json:"target"`
	GeneratedAt    string          `json:"generated_at"`
	ExportTarget   string          `json:"export_target"`
	Subdomains     []string        `json:"subdomains"`
	LiveHosts      []string        `json:"live_hosts"`
	PassiveURLs    []string        `json:"passive_urls"`
	JSFiles        []string        `json:"js_files"`
	Endpoints      []string        `json:"endpoints"`
	EndpointProbes []EndpointProbe `json:"endpoint_probes"`
	Warnings       []string        `json:"warnings"`
	Findings       []Finding       `json:"findings"`
	Profile        Profile         `json:"profile"`
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

type EndpointProbe struct {
	Endpoint        string           `json:"endpoint"`
	URL             string           `json:"url"`
	GETStatus       int              `json:"get_status"`
	HEADStatus      int              `json:"head_status,omitempty"`
	OPTIONSStatus   int              `json:"options_status,omitempty"`
	ContentType     string           `json:"content_type,omitempty"`
	Size            int64            `json:"size,omitempty"`
	Allow           string           `json:"allow,omitempty"`
	CORSAllowOrigin string           `json:"cors_allow_origin,omitempty"`
	Classification  string           `json:"classification"`
	Note            string           `json:"note"`
	SensitiveFields []SensitiveField `json:"sensitive_fields,omitempty"`
	RiskScore       int              `json:"risk_score,omitempty"`
	Risk            string           `json:"risk,omitempty"`
}

type SensitiveField struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Severity string `json:"severity"`
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
	b.WriteString("<title>Reconixia Report - " + esc(r.Target) + "</title>")
	b.WriteString(styles())
	b.WriteString("</head><body><main>")
	b.WriteString("<header><h1>Reconixia Report</h1><p>Target <b>" + esc(r.Target) + "</b> · Profile <b>" + esc(r.Profile.Name) + "</b> · " + esc(r.GeneratedAt) + "</p></header>")
	b.WriteString("<div class=\"grid\">")
	stat(&b, "Subdomains", len(r.Subdomains))
	stat(&b, "Live Hosts", len(r.LiveHosts))
	stat(&b, "Passive URLs", len(r.PassiveURLs))
	stat(&b, "JS Files", len(r.JSFiles))
	stat(&b, "Endpoints", len(r.Endpoints))
	stat(&b, "Endpoint Probes", len(r.EndpointProbes))
	stat(&b, "Findings", len(r.Findings))
	b.WriteString("</div>")
	listSection(&b, "Warnings", r.Warnings)
	endpointProbesSection(&b, r.EndpointProbes)
	findingsSection(&b, r.Findings)
	listSection(&b, "Live Hosts", r.LiveHosts)
	listSection(&b, "JS Files", r.JSFiles)
	listSection(&b, "Endpoint Candidates", r.Endpoints)
	b.WriteString(script())
	b.WriteString("</main></body></html>")
	return b.String()
}

func styles() string {
	return `<style>
:root{--bg:#0b1020;--panel:#111827;--panel2:#0f172a;--muted:#94a3b8;--text:#e5e7eb;--line:#263244;--bad:#f87171;--warn:#fbbf24;--info:#38bdf8;--good:#34d399;--focus:#60a5fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.45}main{max-width:1240px;margin:0 auto;padding:28px 18px 72px}
header{border:1px solid var(--line);border-radius:8px;background:var(--panel2);padding:18px 20px}h1{margin:0 0 6px;font-size:28px;letter-spacing:0}h2{margin:0 0 14px;font-size:18px}p{margin:0;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}.stat span{color:var(--muted);display:block}.stat b{font-size:24px;display:block}
section{margin-top:18px;border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:16px}.toolbar{display:grid;grid-template-columns:1.5fr 1fr 1fr auto;gap:10px;margin-bottom:12px}.toolbar label{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}
input,select{width:100%;background:#0b1220;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px;font:inherit}input:focus,select:focus{outline:2px solid var(--focus);outline-offset:1px}
.toggle{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;white-space:nowrap}.toggle input{width:auto}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:#cbd5e1;font-weight:600;font-size:13px}tbody tr[hidden]{display:none}
.tag{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;border:1px solid var(--line);white-space:nowrap}.high{color:var(--bad)}.medium{color:var(--warn)}.low{color:var(--info)}.info{color:var(--muted)}.critical{color:var(--bad);font-weight:700}code{word-break:break-all;color:#d8b4fe}.empty{color:var(--muted);font-style:italic}.counter{color:var(--muted);font-size:13px;margin:8px 0 0}
ul{margin:0;padding-left:20px}li{margin:6px 0}@media(max-width:920px){.grid{grid-template-columns:repeat(2,1fr)}.toolbar{grid-template-columns:1fr}.toggle{justify-content:flex-start}td,th{font-size:13px}}
</style>`
}

func stat(b *strings.Builder, title string, value int) {
	b.WriteString("<div class=\"stat\"><span>" + esc(title) + "</span><b>")
	b.WriteString(fmt.Sprint(value))
	b.WriteString("</b></div>")
}

func endpointProbesSection(b *strings.Builder, probes []EndpointProbe) {
	b.WriteString("<section><h2>Endpoint Probes</h2>")
	if len(probes) == 0 {
		b.WriteString("<p class=\"empty\">No endpoint probes.</p></section>")
		return
	}
	b.WriteString(`<table><thead><tr><th>Classification</th><th>URL</th><th>GET</th><th>HEAD</th><th>OPTIONS</th><th>Risk</th><th>Sensitive Fields</th><th>Content Type</th><th>Size</th><th>Note</th></tr></thead><tbody>`)
	for _, p := range probes {
		class := endpointClass(p.Classification)
		b.WriteString("<tr>")
		b.WriteString("<td><span class=\"tag " + esc(class) + "\">" + esc(p.Classification) + "</span></td>")
		b.WriteString("<td><code>" + esc(p.URL) + "</code></td>")
		b.WriteString("<td>" + fmt.Sprint(p.GETStatus) + "</td>")
		b.WriteString("<td>" + fmt.Sprint(p.HEADStatus) + "</td>")
		b.WriteString("<td>" + fmt.Sprint(p.OPTIONSStatus) + "</td>")
		b.WriteString("<td>" + endpointRisk(p) + "</td>")
		b.WriteString("<td>" + esc(summarizeSensitiveFields(p.SensitiveFields)) + "</td>")
		b.WriteString("<td>" + esc(p.ContentType) + "</td>")
		b.WriteString("<td>" + fmt.Sprint(p.Size) + "</td>")
		b.WriteString("<td>" + esc(p.Note) + "</td>")
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></section>")
}

func endpointClass(classification string) string {
	switch strings.ToLower(classification) {
	case "public_json_sensitive":
		return "high"
	case "public_json":
		return "high"
	case "auth_required", "method_not_allowed":
		return "info"
	case "forbidden", "rate_limited", "server_error":
		return "medium"
	default:
		return "low"
	}
}

func endpointRisk(p EndpointProbe) string {
	if p.RiskScore <= 0 {
		return ""
	}
	return "<span class=\"tag " + esc(normalizeConfidence(p.Risk)) + "\">" + esc(p.Risk) + "/" + fmt.Sprint(p.RiskScore) + "</span>"
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

func findingsSection(b *strings.Builder, findings []Finding) {
	b.WriteString("<section><h2>Priority Findings</h2>")
	if len(findings) == 0 {
		b.WriteString("<p class=\"empty\">No findings.</p></section>")
		return
	}
	types := findingTypes(findings)
	b.WriteString(`<div class="toolbar">
<div><label for="findingSearch">Search</label><input id="findingSearch" type="search" placeholder="asset, note, type"></div>
<div><label for="typeFilter">Type</label><select id="typeFilter"><option value="">All types</option>`)
	for _, t := range types {
		b.WriteString("<option value=\"" + esc(strings.ToLower(t)) + "\">" + esc(t) + "</option>")
	}
	b.WriteString(`</select></div>
<div><label for="confidenceFilter">Confidence</label><select id="confidenceFilter"><option value="">All confidence</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option><option value="info">info</option></select></div>
<label class="toggle"><input id="highOnly" type="checkbox"> High confidence only</label>
</div>`)
	b.WriteString(`<table id="findingsTable"><thead><tr><th>Type</th><th>URL</th><th>Status</th><th>Confidence</th><th>Note</th></tr></thead><tbody>`)
	for _, f := range findings {
		conf := normalizeConfidence(f.Confidence)
		rowText := strings.ToLower(f.Type + " " + f.URL + " " + f.Note + " " + f.Confidence)
		b.WriteString("<tr data-type=\"" + esc(strings.ToLower(f.Type)) + "\" data-confidence=\"" + esc(conf) + "\" data-text=\"" + esc(rowText) + "\">")
		b.WriteString("<td><span class=\"tag\">" + esc(f.Type) + "</span></td><td><code>" + esc(f.URL) + "</code></td><td>")
		b.WriteString(fmt.Sprint(f.Status))
		b.WriteString("</td><td class=\"" + esc(conf) + "\">" + esc(f.Confidence) + "</td><td>" + esc(f.Note) + "</td></tr>")
	}
	b.WriteString("</tbody></table><div id=\"findingCounter\" class=\"counter\"></div></section>")
}

func findingTypes(findings []Finding) []string {
	set := map[string]bool{}
	for _, f := range findings {
		if strings.TrimSpace(f.Type) != "" {
			set[f.Type] = true
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func normalizeConfidence(conf string) string {
	c := strings.ToLower(strings.TrimSpace(conf))
	switch c {
	case "critical", "high", "medium", "low", "info":
		return c
	default:
		return "info"
	}
}

func listSection(b *strings.Builder, title string, values []string) {
	b.WriteString("<section><h2>" + esc(title) + "</h2>")
	if len(values) == 0 {
		b.WriteString("<p class=\"empty\">No records.</p></section>")
		return
	}
	b.WriteString("<ul>")
	limit := len(values)
	if limit > 250 {
		limit = 250
	}
	for i := 0; i < limit; i++ {
		b.WriteString("<li><code>" + esc(values[i]) + "</code></li>")
	}
	if len(values) > limit {
		b.WriteString("<li class=\"empty\">... " + fmt.Sprint(len(values)-limit) + " more records in report.json.</li>")
	}
	b.WriteString("</ul></section>")
}

func script() string {
	return `<script>
const rows=[...document.querySelectorAll("#findingsTable tbody tr")];
const search=document.querySelector("#findingSearch");
const typeFilter=document.querySelector("#typeFilter");
const confidenceFilter=document.querySelector("#confidenceFilter");
const highOnly=document.querySelector("#highOnly");
const counter=document.querySelector("#findingCounter");
function applyFilters(){
  const q=(search?.value||"").trim().toLowerCase();
  const type=typeFilter?.value||"";
  const conf=confidenceFilter?.value||"";
  let visible=0;
  rows.forEach(row=>{
    const rowConf=row.dataset.confidence||"info";
    const okSearch=!q || (row.dataset.text||"").includes(q);
    const okType=!type || row.dataset.type===type;
    const okConf=!conf || rowConf===conf;
    const okHigh=!highOnly?.checked || rowConf==="critical" || rowConf==="high";
    const show=okSearch && okType && okConf && okHigh;
    row.hidden=!show;
    if(show) visible++;
  });
  if(counter) counter.textContent=visible + " / " + rows.length + " visible";
}
[search,typeFilter,confidenceFilter,highOnly].forEach(el=>el&&el.addEventListener("input",applyFilters));
applyFilters();
</script>`
}

func esc(s string) string { return html.EscapeString(s) }
