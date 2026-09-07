package takeover

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

// AnalyzeSubdomains performs a passive DNS/CNAME takeover precursor check.
// It never attempts to claim a resource; it only emits manual review candidates.
func AnalyzeSubdomains(hosts []string, rules []string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, raw := range hosts {
		host, ok := safety.NormalizeTarget(raw)
		if !ok || seen[host] {
			continue
		}
		seen[host] = true
		if !safety.ScopeAllowsURL("https://"+host, rules) {
			continue
		}
		out = append(out, analyzeHost(host)...)
	}
	return out
}

func analyzeHost(host string) []Finding {
	resolver := net.DefaultResolver
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	cname, err := resolver.LookupCNAME(ctx, host)
	if err != nil || cname == "" {
		return nil
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	fp, ok := DetectProvider(cname)
	if !ok {
		return nil
	}

	ctxIP, cancelIP := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancelIP()
	ips, _ := resolver.LookupIPAddr(ctxIP, host)
	if len(ips) == 0 {
		return []Finding{{
			Type:       "possible_subdomain_takeover",
			URL:        host,
			Status:     0,
			Confidence: fp.Confidence,
			Note:       "CNAME " + cname + " provider=" + fp.Provider + " evidence=" + fp.Evidence + "; no A/AAAA resolution; manual takeover verification required",
		}}
	}
	return []Finding{{
		Type:       "takeover_surface",
		URL:        host,
		Status:     0,
		Confidence: "info",
		Note:       "CNAME " + cname + " provider=" + fp.Provider + " evidence=" + fp.Evidence + "; active DNS resolution exists; verify service ownership manually",
	}}
}
