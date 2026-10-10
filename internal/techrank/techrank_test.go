package techrank

import "testing"

func TestRankOrdersByRiskThenHosts(t *testing.T) {
	lines := []string{
		`{"url":"https://a.example.com","tech":["nginx","Grafana"]}`,
		`{"url":"https://b.example.com","tech":["nginx"]}`,
		`{"url":"https://c.example.com","technologies":["jQuery"]}`,
		`not-json-should-be-skipped`,
	}
	items := Rank(lines)
	if len(items) == 0 {
		t.Fatal("beklenen teknolojiler boş döndü")
	}
	// Grafana is high-risk and must rank first.
	if items[0].Name != "grafana" || items[0].Risk != "high" {
		t.Fatalf("ilk sıra grafana/high bekleniyordu, gelen: %q/%q", items[0].Name, items[0].Risk)
	}
	// nginx is medium-risk, seen on 2 hosts.
	var nginx *Item
	for i := range items {
		if items[i].Name == "nginx" {
			nginx = &items[i]
		}
	}
	if nginx == nil || nginx.Risk != "medium" || nginx.Hosts != 2 {
		t.Fatalf("nginx medium/2 host bekleniyordu, gelen: %+v", nginx)
	}
}

func TestStripVersion(t *testing.T) {
	if got := stripVersion("nginx:1.25.3"); got != "nginx" {
		t.Fatalf("stripVersion hatalı: %q", got)
	}
}
