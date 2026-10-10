// Package techrank turns httpx technology fingerprints into a risk-ranked
// summary. It is a pure, local transform over httpx JSONL output — it sends no
// traffic of its own.
package techrank

import (
	"encoding/json"
	"sort"
	"strings"
)

// Item is one technology aggregated across the hosts it was seen on.
type Item struct {
	Name     string   `json:"name"`
	Risk     string   `json:"risk"`
	Hosts    int      `json:"hosts"`
	Examples []string `json:"examples,omitempty"`
}

type httpxLine struct {
	URL          string   `json:"url"`
	Input        string   `json:"input"`
	Tech         []string `json:"tech"`
	Technologies []string `json:"technologies"`
}

// highRisk lists technologies whose exposure is, on its own, worth prioritising
// during triage (admin surfaces, dev tooling, historically heavy CVE targets).
var highRisk = map[string]bool{
	"jenkins": true, "gitlab": true, "grafana": true, "kibana": true,
	"elasticsearch": true, "jira": true, "confluence": true, "phpmyadmin": true,
	"adminer": true, "tomcat": true, "jboss": true, "weblogic": true,
	"struts": true, "wordpress": true, "drupal": true, "joomla": true,
	"magento": true, "spring boot": true, "spring": true, "django": true,
	"laravel": true, "symfony": true, "graphql": true, "swagger ui": true,
	"swagger": true, "kubernetes": true, "docker": true, "coldfusion": true,
	"citrix": true, "fortinet": true, "sonarqube": true, "rabbitmq": true,
	"prometheus": true, "harbor": true, "keycloak": true,
}

// mediumRisk lists common web-stack components: useful context, moderate signal.
var mediumRisk = map[string]bool{
	"php": true, "apache": true, "apache httpd": true, "nginx": true,
	"microsoft-iis": true, "iis": true, "express": true, "node.js": true,
	"nodejs": true, "openresty": true, "tornado": true, "flask": true,
	"ruby on rails": true, "rails": true, "asp.net": true, "next.js": true,
	"nuxt.js": true, "varnish": true, "haproxy": true, "wordpress plugin": true,
}

// Rank reads httpx JSONL (one object per line) and returns technologies ordered
// high → medium → low risk, then by host count.
func Rank(jsonlLines []string) []Item {
	type agg struct {
		risk     string
		hosts    map[string]bool
		examples []string
	}
	byTech := map[string]*agg{}

	for _, line := range jsonlLines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var hl httpxLine
		if err := json.Unmarshal([]byte(line), &hl); err != nil {
			continue
		}
		host := hl.URL
		if host == "" {
			host = hl.Input
		}
		techs := hl.Tech
		if len(techs) == 0 {
			techs = hl.Technologies
		}
		for _, t := range techs {
			name := strings.TrimSpace(t)
			if name == "" {
				continue
			}
			key := strings.ToLower(stripVersion(name))
			a := byTech[key]
			if a == nil {
				a = &agg{risk: riskOf(key), hosts: map[string]bool{}}
				byTech[key] = a
			}
			if host != "" && !a.hosts[host] {
				a.hosts[host] = true
				if len(a.examples) < 3 {
					a.examples = append(a.examples, host)
				}
			}
		}
	}

	out := make([]Item, 0, len(byTech))
	for name, a := range byTech {
		out = append(out, Item{Name: name, Risk: a.risk, Hosts: len(a.hosts), Examples: a.examples})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rankOf(out[i].Risk) != rankOf(out[j].Risk) {
			return rankOf(out[i].Risk) < rankOf(out[j].Risk)
		}
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts > out[j].Hosts
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func stripVersion(s string) string {
	// httpx often reports "nginx:1.25.3" or "PHP 8.2" — keep the product name.
	if i := strings.IndexAny(s, ":"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func riskOf(key string) string {
	if highRisk[key] {
		return "high"
	}
	if mediumRisk[key] {
		return "medium"
	}
	return "low"
}

func rankOf(risk string) int {
	switch risk {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}
