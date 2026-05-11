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

type signature struct {
	Provider string
	Needle   string
}

var danglingCNAMESignatures = []signature{
	{"aws_s3", "amazonaws.com"},
	{"github_pages", "github.io"},
	{"heroku", "herokuapp.com"},
	{"azure", "azurewebsites.net"},
	{"azure_traffic_manager", "trafficmanager.net"},
	{"fastly", "fastly.net"},
	{"netlify", "netlify.app"},
	{"vercel", "vercel.app"},
	{"surge", "surge.sh"},
	{"shopify", "myshopify.com"},
}

// AnalyzeSubdomains performs a passive DNS/CNAME takeover precursor check.
// It does not exploit anything; it only flags CNAMEs that point to common SaaS/CDN providers
// and have no A/AAAA resolution, which may indicate a dangling record needing manual review.
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
	provider := detectProvider(cname)
	if provider == "" {
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
			Confidence: "medium",
			Note:       "CNAME " + cname + " provider=" + provider + " fakat A/AAAA çözümü yok; manuel subdomain takeover kontrolü gerekir",
		}}
	}
	return []Finding{{
		Type:       "takeover_surface",
		URL:        host,
		Status:     0,
		Confidence: "info",
		Note:       "CNAME " + cname + " provider=" + provider + "; aktif çözüm var, yine de servis sahipliği manuel doğrulanabilir",
	}}
}

func detectProvider(cname string) string {
	for _, s := range danglingCNAMESignatures {
		if strings.Contains(cname, s.Needle) {
			return s.Provider
		}
	}
	return ""
}
