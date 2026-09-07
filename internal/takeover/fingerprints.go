package takeover

import "strings"

// ProviderFingerprint describes passive takeover indicators for a SaaS/CDN provider.
// These fingerprints are intentionally conservative: Reconixia flags manual review
// candidates and never attempts to claim or modify third-party resources.
type ProviderFingerprint struct {
	Provider   string
	Needles    []string
	Evidence   string
	Confidence string
}

var ProviderFingerprints = []ProviderFingerprint{
	{Provider: "aws_s3", Needles: []string{"amazonaws.com", "s3.amazonaws.com"}, Evidence: "S3-style CNAME", Confidence: "medium"},
	{Provider: "github_pages", Needles: []string{"github.io"}, Evidence: "GitHub Pages CNAME", Confidence: "medium"},
	{Provider: "heroku", Needles: []string{"herokuapp.com", "herokudns.com"}, Evidence: "Heroku CNAME", Confidence: "medium"},
	{Provider: "azure_app_service", Needles: []string{"azurewebsites.net"}, Evidence: "Azure App Service CNAME", Confidence: "medium"},
	{Provider: "azure_traffic_manager", Needles: []string{"trafficmanager.net"}, Evidence: "Azure Traffic Manager CNAME", Confidence: "medium"},
	{Provider: "fastly", Needles: []string{"fastly.net", "fastlylb.net"}, Evidence: "Fastly CNAME", Confidence: "low"},
	{Provider: "netlify", Needles: []string{"netlify.app", "netlifyglobalcdn.com"}, Evidence: "Netlify CNAME", Confidence: "medium"},
	{Provider: "vercel", Needles: []string{"vercel.app", "zeit.world", "now.sh"}, Evidence: "Vercel CNAME", Confidence: "medium"},
	{Provider: "surge", Needles: []string{"surge.sh"}, Evidence: "Surge CNAME", Confidence: "medium"},
	{Provider: "shopify", Needles: []string{"myshopify.com"}, Evidence: "Shopify CNAME", Confidence: "low"},
	{Provider: "readme", Needles: []string{"readme.io"}, Evidence: "ReadMe CNAME", Confidence: "medium"},
	{Provider: "pantheon", Needles: []string{"pantheonsite.io"}, Evidence: "Pantheon CNAME", Confidence: "medium"},
	{Provider: "unbounce", Needles: []string{"unbouncepages.com"}, Evidence: "Unbounce CNAME", Confidence: "medium"},
}

func DetectProvider(name string) (ProviderFingerprint, bool) {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, fp := range ProviderFingerprints {
		for _, needle := range fp.Needles {
			if strings.Contains(normalized, strings.ToLower(needle)) {
				return fp, true
			}
		}
	}
	return ProviderFingerprint{}, false
}
